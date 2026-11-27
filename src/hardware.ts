import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { arch as osArch, cpus, hostname, networkInterfaces, platform as osPlatform } from "node:os";

const VM_MARKERS = ["vmware", "virtualbox", "kvm", "qemu", "xen", "hyper-v", "virtual machine",
  "parallels", "bochs", "bhyve", "google compute engine", "amazon ec2", "openstack"];

function run(cmd: string, args: string[]): string {
  try { return execFileSync(cmd, args, { encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"] }); } catch { return ""; }
}

export function machineId(): string {
  const p = osPlatform();
  if (p === "win32") {
    const m = /MachineGuid\s+REG_SZ\s+(\S+)/.exec(run("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"]));
    if (m) return m[1];
  } else if (p === "darwin") {
    const m = /"IOPlatformUUID"\s*=\s*"([^"]+)"/.exec(run("ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"]));
    if (m) return m[1];
  } else {
    for (const f of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
      try { const v = readFileSync(f, "utf8").trim(); if (v) return v; } catch { /* next */ }
    }
  }
  throw new Error("machine id not found");
}

/** Salted SHA-256 of one hardware value (the raw value never leaves the machine). */
export function hashComponent(salt: string, name: string, value: string): string {
  const v = value.trim().toLowerCase();
  return createHash("sha256").update(name ? `${salt}:${name}:${v}` : `${salt}:${v}`).digest("hex");
}

/** SHA-256 of the OS machine id salted with `salt`: 64 hex characters. */
export function machineFingerprint(salt: string): string {
  return hashComponent(salt, "", machineId());
}

export function looksVirtual(s: string): boolean {
  const l = s.toLowerCase();
  return VM_MARKERS.some((m) => l.includes(m));
}

export function isVirtual(): boolean {
  const p = osPlatform();
  if (p === "linux") {
    for (const f of ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor"]) {
      try { if (looksVirtual(readFileSync(f, "utf8"))) return true; } catch { /* next */ }
    }
    if (existsSync("/.dockerenv")) return true;
    try {
      const cg = readFileSync("/proc/1/cgroup", "utf8");
      if (["docker", "kubepods", "containerd", "lxc"].some((w) => cg.includes(w))) return true;
    } catch { /* none */ }
  } else if (p === "darwin") {
    return run("sysctl", ["-n", "kern.hv_vmm_present"]).trim() === "1";
  } else if (p === "win32") {
    for (const v of ["SystemProductName", "SystemManufacturer"]) {
      if (looksVirtual(run("reg", ["query", "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS", "/v", v]))) return true;
    }
  }
  return false;
}

function primaryMac(): string {
  const ifs = networkInterfaces();
  for (const name of Object.keys(ifs).sort()) {
    const n = name.toLowerCase();
    if (n.startsWith("docker") || n.startsWith("veth") || n.startsWith("br-") || n.startsWith("virbr")) continue;
    for (const a of ifs[name] ?? []) {
      if (!a.internal && a.mac && a.mac !== "00:00:00:00:00:00") return a.mac;
    }
  }
  return "";
}

export interface HardwareInfo { components: Record<string, string>; virtual: boolean }

/** Hashed components (machine_id, hostname, mac, cpu, os) and the VM flag. */
export function collectHardware(salt: string): HardwareInfo {
  const components: Record<string, string> = {};
  const add = (name: string, value: string) => { if (value.trim()) components[name] = hashComponent(salt, name, value); };
  try { add("machine_id", machineId()); } catch { /* not readable */ }
  add("hostname", hostname());
  add("mac", primaryMac());
  const c = cpus();
  add("cpu", `${c[0]?.model ?? ""}|${c.length}`);
  add("os", `${osPlatform()}|${osArch()}`);
  return { components, virtual: isVirtual() };
}
