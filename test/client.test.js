import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { APIError, BadSignatureError, ChecksumError, Client, collectHardware, keyId, looksVirtual, verifyToken } from "../dist/index.js";

const vector = JSON.parse(readFileSync(new URL("../testdata/token-v2.json", import.meta.url), "utf8"));
const KEY = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";

test("server vector verifies, kid matches, manifest verifies", () => {
  assert.equal(keyId(vector.public_key_hex), vector.kid);
  const tok = verifyToken(vector.public_key_hex, vector.response.data);
  const fp = tok.payload.machine_fingerprint;
  const now = new Date("2026-11-30T00:00:00Z");
  assert.equal(tok.payload.license_model, "node_locked");
  assert.ok(tok.canRun(fp, new Date("2027-01-01T00:00:00Z"), now));
  assert.ok(!tok.canRun(fp, new Date("2027-08-01T00:00:00Z"), now));
  const raw = Buffer.from(vector.response.data.payload, "base64").toString().replace('"valid"', '"VALID"');
  assert.throws(() => verifyToken(vector.public_key_hex, { ...vector.response.data, payload: Buffer.from(raw).toString("base64") }), BadSignatureError);
  const m = JSON.parse(Buffer.from(vector.update_manifest.payload, "base64").toString());
  assert.equal(m.latest.sha256, createHash("sha256").update("binary").digest("hex"));
});

function fakeApi() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubHex = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
  const api = { pubHex, kid: keyId(pubHex), floating: false, approved: false, seats: new Set(), used: 0, seen: new Set(), deviceFp: "" };
  const signObj = (o) => { const p = Buffer.from(JSON.stringify(o)); return { alg: "Ed25519", kid: api.kid, payload: p.toString("base64"), signature: sign(null, p, privateKey).toString("base64") }; };
  api.sign = signObj;
  const token = (fp, nonce, auth = "key", validMs = 48 * 3600e3, extra = {}) => {
    const now = Date.now();
    return signObj({ v: 2, status: "valid", machine_fingerprint: fp, nonce, updates_policy: "lifetime", license_model: api.floating ? "floating" : "node_locked", auth,
      features: [], issued_at: new Date(now).toISOString(), checkin_after: new Date(now + validMs / 2).toISOString(), valid_until: new Date(now + validMs).toISOString(), ...extra });
  };
  api.server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      const body = JSON.parse(b || "{}");
      const send = (status, obj) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(obj));
      const ok = body.license_key === KEY || body.activation_secret === "secret-1";
      const valid = api.floating ? 600e3 : 48 * 3600e3;
      switch (req.url) {
        case "/activate": case "/validate":
          if (!ok) return send(404, { error: "license_not_found" });
          if (api.floating) {
            if (!api.seats.has(body.machine_fingerprint) && api.seats.size >= 1) return send(409, { error: "no_seat_available" });
            api.seats.add(body.machine_fingerprint);
          }
          return send(200, { data: token(body.machine_fingerprint, body.nonce, body.activation_secret ? "user" : "key", valid) });
        case "/deactivate": api.seats.delete(body.machine_fingerprint); return send(200, { data: {} });
        case "/trials/start":
          return send(200, { data: { license_key: "TTTTT-TTTTT-TTTTT-TTTTT-TTTTT", token: token(body.machine_fingerprint, body.nonce, "key", valid,
            { license_type: "trial", expires_at: new Date(Date.now() + 14 * 86400e3).toISOString() }) } });
        case "/device/start": api.deviceFp = body.machine_fingerprint;
          return send(200, { data: { device_code: "dev-1", user_code: "ABCD-EFGH", verification_url: "https://shop/account/device", expires_in: 900, interval: 0 } });
        case "/device/poll":
          if (!api.approved) return send(200, { data: { status: "pending" } });
          return send(200, { data: { status: "approved", activation_secret: "secret-1", token: token(api.deviceFp, body.nonce, "user", valid) } });
        case "/usage": {
          let amount = body.amount;
          if (body.idempotency_key && api.seen.has(body.idempotency_key)) amount = 0;
          if (api.used + amount > 3) return send(409, { error: "usage_limit_reached" });
          api.used += amount;
          if (body.idempotency_key) api.seen.add(body.idempotency_key);
          return send(200, { data: signObj({ kind: "usage", meter: body.meter, used: api.used, limit: 3, remaining: 3 - api.used, machine_fingerprint: body.machine_fingerprint, nonce: body.nonce }) });
        }
        case "/updates/check":
          return send(200, { data: { manifest: signObj({ kind: "update", machine_fingerprint: body.machine_fingerprint, nonce: body.nonce, update_available: true,
            latest: { version: "2.0.0", file_id: "f-1", sha256: createHash("sha256").update("binary").digest("hex") } }) } });
        case "/releases/download": return res.writeHead(200).end("binary");
        default: return send(404, {});
      }
    });
  });
  return api;
}

async function withApi(fn) {
  const api = fakeApi();
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  api.base = `http://127.0.0.1:${api.server.address().port}`;
  try { await fn(api); } finally { await new Promise((r) => api.server.close(r)); }
}

const dir = () => mkdtempSync(join(tmpdir(), "lic-"));
const make = (api, fp, cachePath, extra = {}) => new Client({ tenant: "shop", publicKeyHex: api.pubHex, fingerprint: fp, productId: "p-1", baseUrl: api.base, cachePath, ...extra });

test("activate, check, offline grace", async () => {
  const api = fakeApi();
  await new Promise((r) => api.server.listen(0, "127.0.0.1", r));
  api.base = `http://127.0.0.1:${api.server.address().port}`;
  const cache = join(dir(), "licence.json");
  const c = make(api, "fp-1", cache);
  await assert.rejects(c.activate("zzzzz-zzzzz-zzzzz-zzzzz-zzzzz"), (e) => e instanceof APIError && e.code === "license_not_found");
  await c.activate(KEY.toLowerCase());
  assert.ok((await c.check()).canRun);
  await new Promise((r) => api.server.close(r));
  const later = make(api, "fp-1", cache, { now: () => new Date(Date.now() + 30 * 3600e3) });
  const st = await later.check();
  assert.ok(st.canRun && !st.online);
  assert.ok(!(await make(api, "fp-1", cache, { now: () => new Date(Date.now() + 72 * 3600e3) }).check()).canRun);
});

test("key rotation accepts the extra key", () => withApi(async (api) => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const oldHex = publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
  await make(api, "fp", join(dir(), "a.json"), { publicKeyHex: oldHex, extraPublicKeysHex: [api.pubHex] }).activate(KEY);
  await assert.rejects(make(api, "fp", join(dir(), "b.json"), { publicKeyHex: oldHex }).activate(KEY), BadSignatureError);
}));

test("floating seat and release", () => withApi(async (api) => {
  api.floating = true;
  const a = make(api, "fp-a", join(dir(), "a.json")), b = make(api, "fp-b", join(dir(), "b.json"));
  assert.equal((await a.activate(KEY)).payload.license_model, "floating");
  await assert.rejects(b.activate(KEY), (e) => e.code === "no_seat_available");
  await a.release();
  assert.ok(a.licenseKey);
  await b.activate(KEY);
}));

test("trial and sign-in", () => withApi(async (api) => {
  const cache = join(dir(), "licence.json");
  const c = make(api, "fp-1", cache);
  const tr = await c.startTrial("me@example.com");
  assert.ok(tr.isTrial && tr.trialDaysLeft(new Date()) >= 13);
  const s = await c.startSignIn();
  assert.equal(s.userCode, "ABCD-EFGH");
  assert.equal(await c.pollSignIn(s), null);
  api.approved = true;
  const tok = await c.waitForSignIn(s);
  assert.equal(tok.payload.auth, "user");
  assert.ok(c.signedIn && (await c.check()).canRun);
  assert.ok(make(api, "fp-1", cache).signedIn);
}));

test("usage, updates and download", () => withApi(async (api) => {
  const c = make(api, "fp-1", join(dir(), "licence.json"));
  await c.activate(KEY);
  assert.equal((await c.reportUsage("exports", 2, "job-1")).used, 2);
  assert.equal((await c.reportUsage("exports", 2, "job-1")).used, 2);
  await assert.rejects(c.reportUsage("exports", 2, "job-2"), (e) => e.code === "usage_limit_reached");
  const m = await c.checkForUpdate();
  assert.ok(m.update_available && m.latest);
  assert.equal((await c.download(m.latest)).toString(), "binary");
  await assert.rejects(c.download({ ...m.latest, sha256: "0".repeat(64) }), ChecksumError);
}));

test("offline request and import", async () => {
  const api = fakeApi();
  const cache = join(dir(), "licence.json");
  const c = make(api, "fp-air", cache);
  const req = JSON.parse(Buffer.from(c.offlineRequest(KEY), "base64").toString());
  assert.equal(req.kind, "offline_request");
  const now = Date.now();
  const answer = (nonce) => JSON.stringify({ kind: "dirora_offline_licence", v: 1, token: api.sign({ v: 2, status: "valid", machine_fingerprint: "fp-air", nonce, offline: true,
    updates_policy: "lifetime", features: [], issued_at: new Date(now).toISOString(), checkin_after: new Date(now + 365 * 86400e3).toISOString(), valid_until: new Date(now + 365 * 86400e3).toISOString() }) });
  assert.throws(() => c.importOfflineLicence(answer("other")), BadSignatureError);
  assert.ok(c.importOfflineLicence(answer(req.nonce)).payload.offline);
  const st = await make(api, "fp-air", cache).check(); // no server at all
  assert.ok(st.canRun && !st.error);
});

test("hardware is hashed", () => {
  const hw = collectHardware("shop");
  assert.ok(Object.values(hw.components).every((v) => v.length === 64));
  assert.ok(looksVirtual("VMware Virtual Platform") && !looksVirtual("ThinkPad X1"));
});
