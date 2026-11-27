/**
 * Dirora software-licensing client for Node.js (18+) and Electron.
 *
 * ```ts
 * import { Client } from "@dirora/license";
 * const client = new Client({
 *   tenant: "your-shop",
 *   publicKeyHex: "79b5…",             // Admin › Licences › For developers
 *   appVersion: "2.4.0",
 *   buildDate: new Date("2026-11-01T00:00:00Z"),
 *   cachePath: path.join(os.homedir(), ".your-app", "licence.json"),
 * });
 * await client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");
 * const state = await client.check();   // on every start
 * if (!state.canRun) process.exit(1);
 * ```
 */
import { createHash, createPublicKey, randomBytes, verify as edVerify, KeyObject } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { hostname, platform as osPlatform, arch as osArch } from "node:os";
import { collectHardware, machineFingerprint, type HardwareInfo } from "./hardware.js";

export { collectHardware, machineFingerprint, looksVirtual, hashComponent } from "./hardware.js";
export type { HardwareInfo } from "./hardware.js";

export const DEFAULT_BASE_URL = "https://api.dirora.com/api/licenses/v";

/** Stable error codes of the licence API. */
export const ErrorCodes = {
  invalidRequest: "invalid_request",
  tenantNotFound: "tenant_not_found",
  licenseNotFound: "license_not_found",
  keyReplaced: "key_replaced",
  licenseBlocked: "license_blocked",
  activationLimit: "activation_limit_reached",
  activationCodeRequired: "activation_code_required",
  activationCodeInvalid: "activation_code_invalid",
  machineNotActivated: "machine_not_activated",
  releaseNotFound: "release_not_found",
  updateNotCovered: "update_not_covered",
  fileUnavailable: "file_unavailable",
  virtualMachine: "virtual_machine_not_allowed",
  noSeatAvailable: "no_seat_available",
  trialNotAvailable: "trial_not_available",
  trialLimit: "trial_limit_reached",
  signInRequired: "sign_in_required",
  deviceCodeInvalid: "device_code_invalid",
  noSeat: "no_seat",
  usageLimit: "usage_limit_reached",
  meterNotFound: "meter_not_found",
  rateLimited: "rate_limited",
} as const;

/** A refusal from the licence API: `code` is stable, `message` English. */
export class APIError extends Error {
  constructor(public status: number, public code: string, message = "") {
    super(`licence API ${status} ${code}: ${message}`);
    this.name = "APIError";
  }
}
/** The answer was not signed by your shop's key, or not for this request. */
export class BadSignatureError extends Error {
  constructor(msg = "licence answer signature does not verify") { super(msg); this.name = "BadSignatureError"; }
}
/** A downloaded file does not match the signed SHA-256. */
export class ChecksumError extends Error {
  constructor() { super("downloaded file checksum mismatch"); this.name = "ChecksumError"; }
}
/** The person did not allow the sign-in, or it expired. */
export class SignInError extends Error {
  constructor(public reason: "denied" | "expired") { super(`sign-in ${reason}`); this.name = "SignInError"; }
}

export interface SignedToken { alg: string; kid?: string; payload: string; signature: string }

export interface TokenPayload {
  v: number;
  license_id: string;
  product_id: string;
  tenant_id: string;
  machine_fingerprint: string;
  status: "valid" | "lapsed" | "blocked" | string;
  reason?: string;
  license_type: string; // perpetual | subscription | trial
  expires_at?: string;
  updates_policy: string;
  updates_until?: string;
  support_policy: string;
  support_until?: string;
  features: string[];
  issued_at: string;
  checkin_after: string;
  valid_until: string;
  nonce?: string;
  /** node_locked, or floating: a lease — renew (check) and release on exit. */
  license_model?: string;
  /** key | user (signed in) */
  auth?: string;
  seats?: number;
  /** Activated with a licence file; no check-ins. */
  offline?: boolean;
}

const t = (s?: string) => (s ? Date.parse(s) : NaN);

/** A verified licence answer with the date checks. */
export class Token {
  constructor(public readonly payload: TokenPayload) {}
  hasFeature(name: string): boolean { return (this.payload.features ?? []).includes(name); }
  get isTrial(): boolean { return this.payload.license_type === "trial"; }
  trialDaysLeft(now: Date): number {
    const end = t(this.payload.expires_at);
    if (!this.isTrial || Number.isNaN(end) || now.getTime() >= end) return 0;
    return Math.floor((end - now.getTime()) / 86_400_000) + 1;
  }
  /** Whether a build released at `buildDate` is within the updates period. */
  coversBuild(buildDate: Date): boolean {
    if (this.payload.updates_policy !== "term") return true;
    const until = t(this.payload.updates_until);
    return !Number.isNaN(until) && buildDate.getTime() <= until;
  }
  /** The gate before the software starts working. */
  canRun(fingerprint: string, buildDate: Date | undefined, now: Date): boolean {
    const p = this.payload;
    if (p.status === "blocked" || p.machine_fingerprint !== fingerprint) return false;
    const validUntil = t(p.valid_until);
    if (Number.isNaN(validUntil) || now.getTime() > validUntil) return false;
    const issued = t(p.issued_at);
    if (!Number.isNaN(issued) && now.getTime() < issued - 10 * 60_000) return false; // clock set back
    if (p.status === "lapsed" || p.updates_policy === "term") return !buildDate || this.coversBuild(buildDate);
    return p.status === "valid";
  }
  needsCheckin(now: Date): boolean {
    const after = t(this.payload.checkin_after);
    return Number.isNaN(after) || now.getTime() >= after;
  }
}

/** A public key's id: the first 16 hex characters of its SHA-256. */
export function keyId(publicKeyHex: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyHex.trim(), "hex")).digest("hex").slice(0, 16);
}

function publicKeyFromHex(hex: string): KeyObject {
  const raw = Buffer.from(hex.trim(), "hex");
  if (raw.length !== 32) throw new Error("public keys must be 64 hex characters");
  // SPKI DER prefix for an Ed25519 public key.
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

type KeySet = Map<string, KeyObject>;

function keySet(hexes: string[]): KeySet {
  const m: KeySet = new Map();
  for (const h of hexes) m.set(keyId(h), publicKeyFromHex(h));
  return m;
}

/** Verify a signed answer/document with the key named by its kid (or any key). */
function verifyBytes(keys: KeySet, signed: { kid?: string; payload: string; signature: string } | undefined): Buffer {
  if (!signed || typeof signed.payload !== "string" || typeof signed.signature !== "string") throw new BadSignatureError();
  const raw = Buffer.from(signed.payload, "base64");
  const sig = Buffer.from(signed.signature, "base64");
  if (sig.length !== 64) throw new BadSignatureError();
  const candidates = signed.kid ? (keys.has(signed.kid) ? [keys.get(signed.kid)!] : []) : [...keys.values()];
  for (const k of candidates) if (edVerify(null, raw, k, sig)) return raw;
  throw new BadSignatureError();
}

/** Check a signed answer against one shop key and parse its payload. */
export function verifyToken(publicKeyHex: string, signed: SignedToken): Token {
  return new Token(JSON.parse(verifyBytes(keySet([publicKeyHex]), signed).toString("utf8")) as TokenPayload);
}

export function platformName(): string {
  return ({ win32: "windows", darwin: "macos", linux: "linux", android: "android" } as Record<string, string>)[osPlatform()] ?? "any";
}
export function archName(): string {
  return ({ x64: "x64", arm64: "arm64", ia32: "x86" } as Record<string, string>)[osArch()] ?? "any";
}

export interface Config {
  tenant: string;
  publicKeyHex: string;
  /** Further keys to accept (ship old and new during a key rotation). */
  extraPublicKeysHex?: string[];
  /** Product id: trials and sign-in need it. */
  productId?: string;
  baseUrl?: string;
  fingerprint?: string;
  machineLabel?: string;
  appVersion?: string;
  buildDate?: Date;
  cachePath?: string;
  /** Don't send hashed hardware components and the VM flag. */
  disableHardwareInfo?: boolean;
  timeoutMs?: number;
  now?: () => Date;
}

export interface State { token?: Token; canRun: boolean; online: boolean; error?: unknown }

export interface ManifestRelease {
  version: string; channel: string; released_at: string;
  file_id?: string; file_name?: string; file_size?: number; sha256?: string;
}
export interface UpdateInfo { update_available: boolean; latest?: ManifestRelease | null; newer_blocked?: ManifestRelease | null }

export interface SignIn { deviceCode: string; userCode: string; verificationUrl: string; expiresIn: number; interval: number; started: number }

export interface Usage { meter: string; used: number; limit: number; remaining: number; period: string; period_start: string; period_end?: string }

interface CacheFile { license_key?: string; activation_secret?: string; token?: SignedToken; pending_offline_nonce?: string }

/** Talks to the licence API for one installation of your product. */
export class Client {
  private readonly keys: KeySet;
  private readonly base: string;
  private readonly fp: string;
  private readonly now: () => Date;
  private hw?: HardwareInfo;
  licenseKey = "";
  activationSecret = "";

  constructor(private readonly cfg: Config) {
    if (!cfg.tenant) throw new Error("tenant is required");
    this.keys = keySet([cfg.publicKeyHex, ...(cfg.extraPublicKeysHex ?? [])]);
    this.base = (cfg.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fp = cfg.fingerprint || machineFingerprint(cfg.tenant);
    this.now = cfg.now ?? (() => new Date());
    const c = this.loadCache();
    this.licenseKey = c?.license_key ?? "";
    this.activationSecret = c?.activation_secret ?? "";
  }

  get fingerprint(): string { return this.fp; }
  get signedIn(): boolean { return this.activationSecret !== ""; }

  verify(signed: SignedToken): Token {
    return new Token(JSON.parse(verifyBytes(this.keys, signed).toString("utf8")) as TokenPayload);
  }

  private async post(path: string, body: Record<string, unknown>): Promise<Response> {
    const res = await fetch(this.base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.cfg.timeoutMs ?? 30_000),
    });
    if (res.status >= 400) {
      const e = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
      throw new APIError(res.status, e.error ?? "", e.message ?? "");
    }
    return res;
  }

  private async postData<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return ((await (await this.post(path, body)).json()) as { data: T }).data;
  }

  private hardware(): HardwareInfo {
    if (this.cfg.disableHardwareInfo) return { components: {}, virtual: false };
    this.hw ??= collectHardware(this.cfg.tenant);
    return this.hw;
  }

  private clientInfo(body: Record<string, unknown>, nonce?: string): Record<string, unknown> {
    const hw = this.hardware();
    return {
      ...body, tenant: this.cfg.tenant, machine_fingerprint: this.fp, machine_label: this.cfg.machineLabel ?? hostname(),
      platform: platformName(), app_version: this.cfg.appVersion ?? "", components: hw.components, virtual: hw.virtual,
      ...(nonce ? { nonce } : {}),
    };
  }

  private credential(body: Record<string, unknown>): Record<string, unknown> {
    if (this.activationSecret) return { ...body, activation_secret: this.activationSecret };
    if (this.licenseKey) return { ...body, license_key: this.licenseKey };
    throw new APIError(0, ErrorCodes.machineNotActivated, "no licence activated on this machine");
  }

  private accept(signed: SignedToken, nonce: string, store: CacheFile): Token {
    const tok = this.verify(signed);
    if (tok.payload.nonce !== nonce || tok.payload.machine_fingerprint !== this.fp) {
      throw new BadSignatureError("licence answer is not for this request");
    }
    this.saveCache({ ...store, token: signed });
    return tok;
  }

  private async tokenCall(path: string, body: Record<string, unknown>, store: CacheFile): Promise<Token> {
    const nonce = randomBytes(12).toString("hex");
    return this.accept(await this.postData<SignedToken>(path, this.clientInfo(body, nonce)), nonce, store);
  }

  /** Register this machine (or take a floating seat) with a licence key. */
  async activate(licenseKey: string, activationCode = ""): Promise<Token> {
    const key = licenseKey.trim().toUpperCase();
    const tok = await this.tokenCall("/activate", { license_key: key, activation_code: activationCode }, { license_key: key });
    this.licenseKey = key;
    this.activationSecret = "";
    return tok;
  }

  /** Check in online (renews a floating seat). */
  async validate(): Promise<Token> {
    return this.tokenCall("/validate", this.credential({}), { license_key: this.licenseKey, activation_secret: this.activationSecret });
  }

  /** Free a floating seat when the app closes (the licence stays on the machine). */
  async release(): Promise<void> {
    if (!this.licenseKey && !this.activationSecret) return;
    await this.post("/deactivate", this.credential({ tenant: this.cfg.tenant, machine_fingerprint: this.fp }));
  }

  /** Free this machine's place and forget the licence on it. */
  async deactivate(): Promise<void> {
    await this.release();
    this.licenseKey = "";
    this.activationSecret = "";
    if (this.cfg.cachePath) rmSync(this.cfg.cachePath, { force: true });
  }

  /** Start-up routine: cached answer while fresh, online when due, cache as
   *  fallback within the offline grace. Call again before a floating lease ends. */
  async check(): Promise<State> {
    const now = this.now();
    const cached = this.cachedToken();
    const bd = this.cfg.buildDate;
    if (cached && (cached.payload.offline || !cached.needsCheckin(now))) return { token: cached, canRun: cached.canRun(this.fp, bd, now), online: false };
    try {
      const tok = await this.validate();
      return { token: tok, canRun: tok.canRun(this.fp, bd, this.now()), online: true };
    } catch (error) {
      if (error instanceof APIError && error.status > 0 && error.status < 500 && error.status !== 429) return { canRun: false, online: false, error };
      if (cached) return { token: cached, canRun: cached.canRun(this.fp, bd, now), online: false, error };
      return { canRun: false, online: false, error };
    }
  }

  /** Start (or resume) this machine's free trial of `productId`. */
  async startTrial(email = ""): Promise<Token> {
    if (!this.cfg.productId) throw new Error("Config.productId is required for trials");
    const nonce = randomBytes(12).toString("hex");
    const d = await this.postData<{ license_key: string; token: SignedToken }>("/trials/start",
      this.clientInfo({ product_id: this.cfg.productId, email }, nonce));
    const key = d.license_key.toUpperCase();
    const tok = this.accept(d.token, nonce, { license_key: key });
    this.licenseKey = key;
    this.activationSecret = "";
    return tok;
  }

  /** Begin signing this machine in with a customer account: show `userCode`
   *  and open `verificationUrl`, then `waitForSignIn`. */
  async startSignIn(): Promise<SignIn> {
    if (!this.cfg.productId) throw new Error("Config.productId is required for sign-in");
    const d = await this.postData<{ device_code: string; user_code: string; verification_url: string; expires_in: number; interval: number }>(
      "/device/start", this.clientInfo({ product_id: this.cfg.productId }));
    return { deviceCode: d.device_code, userCode: d.user_code, verificationUrl: d.verification_url, expiresIn: d.expires_in, interval: d.interval, started: Date.now() };
  }

  /** Ask once; null while waiting for approval. */
  async pollSignIn(s: SignIn): Promise<Token | null> {
    const nonce = randomBytes(12).toString("hex");
    const d = await this.postData<{ status: string; activation_secret?: string; token?: SignedToken }>(
      "/device/poll", { tenant: this.cfg.tenant, device_code: s.deviceCode, nonce });
    if (d.status === "pending") return null;
    if (d.status === "denied" || d.status === "expired") throw new SignInError(d.status);
    const tok = this.accept(d.token!, nonce, { activation_secret: d.activation_secret });
    this.licenseKey = "";
    this.activationSecret = d.activation_secret ?? "";
    return tok;
  }

  async waitForSignIn(s: SignIn, signal?: AbortSignal): Promise<Token> {
    for (;;) {
      const tok = await this.pollSignIn(s);
      if (tok) return tok;
      if (Date.now() - s.started > s.expiresIn * 1000) throw new SignInError("expired");
      signal?.throwIfAborted();
      await new Promise((r) => setTimeout(r, Math.max(s.interval, 2) * 1000));
    }
  }

  /** Request text for a machine without internet (save as a .req file). */
  offlineRequest(licenseKey: string): string {
    if (!this.cfg.cachePath) throw new Error("Config.cachePath is required for offline activation");
    const nonce = randomBytes(12).toString("hex");
    const hw = this.hardware();
    const req = {
      v: 1, kind: "offline_request", license_key: licenseKey.trim().toUpperCase(), product_id: this.cfg.productId ?? "",
      machine_fingerprint: this.fp, machine_label: this.cfg.machineLabel ?? hostname(), platform: platformName(),
      app_version: this.cfg.appVersion ?? "", nonce, components: hw.components, virtual: hw.virtual,
    };
    this.saveCache({ ...(this.loadCache() ?? {}), pending_offline_nonce: nonce });
    return Buffer.from(JSON.stringify(req)).toString("base64");
  }

  /** Check and store the licence file answering this machine's request. */
  importOfflineLicence(fileContent: string | Buffer): Token {
    let f: { kind?: string; token?: SignedToken };
    try { f = JSON.parse(fileContent.toString()); } catch { throw new Error("not a licence file"); }
    if (f.kind !== "dirora_offline_licence" || !f.token) throw new Error("not a licence file");
    const pending = this.loadCache()?.pending_offline_nonce;
    if (!pending) throw new Error("no offline request is pending on this machine");
    const tok = this.verify(f.token);
    if (!tok.payload.offline || tok.payload.nonce !== pending || tok.payload.machine_fingerprint !== this.fp) {
      throw new BadSignatureError("licence file is not for this request");
    }
    this.saveCache({ token: f.token });
    this.licenseKey = "";
    this.activationSecret = "";
    return tok;
  }

  /** Count `amount` on a usage meter (0 reads it). */
  async reportUsage(meter: string, amount = 1, idempotencyKey = ""): Promise<Usage> {
    const nonce = randomBytes(12).toString("hex");
    const signed = await this.postData<SignedToken>("/usage", this.credential({
      tenant: this.cfg.tenant, machine_fingerprint: this.fp, meter, amount, idempotency_key: idempotencyKey, nonce,
    }));
    const u = JSON.parse(verifyBytes(this.keys, signed).toString("utf8"));
    if (u.kind !== "usage" || u.nonce !== nonce || u.machine_fingerprint !== this.fp) throw new BadSignatureError("usage answer is not for this request");
    return u as Usage;
  }

  /** The verified update manifest for this licence (`channel`: stable | beta). */
  async checkForUpdate(channel = "stable"): Promise<UpdateInfo> {
    const nonce = randomBytes(12).toString("hex");
    const d = await this.postData<{ manifest?: SignedToken }>("/updates/check", this.credential({
      tenant: this.cfg.tenant, machine_fingerprint: this.fp, current_version: this.cfg.appVersion ?? "",
      platform: platformName(), arch: archName(), channel, nonce,
    }));
    const m = JSON.parse(verifyBytes(this.keys, d.manifest).toString("utf8"));
    if (m.kind !== "update" || m.nonce !== nonce || m.machine_fingerprint !== this.fp) throw new BadSignatureError("update answer is not for this request");
    return m as UpdateInfo;
  }

  /** Download a release (from the manifest) and check the signed SHA-256. */
  async download(release: ManifestRelease): Promise<Buffer> {
    const res = await this.post("/releases/download", this.credential({ tenant: this.cfg.tenant, machine_fingerprint: this.fp, file_id: release.file_id }));
    const buf = Buffer.from(await res.arrayBuffer());
    const want = (release.sha256 || res.headers.get("X-Checksum-SHA256") || "").toLowerCase();
    if (want && want !== createHash("sha256").update(buf).digest("hex")) throw new ChecksumError();
    return buf;
  }

  private loadCache(): CacheFile | undefined {
    if (!this.cfg.cachePath) return undefined;
    try { return JSON.parse(readFileSync(this.cfg.cachePath, "utf8")) as CacheFile; } catch { return undefined; }
  }
  private saveCache(f: CacheFile): void {
    if (!this.cfg.cachePath) return;
    const clean = Object.fromEntries(Object.entries(f).filter(([, v]) => v));
    mkdirSync(dirname(this.cfg.cachePath), { recursive: true });
    const tmp = this.cfg.cachePath + ".tmp";
    writeFileSync(tmp, JSON.stringify(clean), { mode: 0o600 });
    renameSync(tmp, this.cfg.cachePath);
  }
  private cachedToken(): Token | undefined {
    const c = this.loadCache();
    if (!c?.token) return undefined;
    try { return this.verify(c.token); } catch { return undefined; }
  }
}
