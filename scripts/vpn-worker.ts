// Builds fran-vpn and puts it where Tauri's externalBin looks for it: src-tauri/binaries/fran-vpn-<target triple>.
// On Windows it also fetches Wintun's signed wintun.dll, which the VPN service needs, checked against its published hash.
// Wintun's license allows shipping that DLL unmodified with an app that only uses wintun.h.
// Tauri runs this before dev and build. By hand: node scripts/vpn-worker.ts [--release]

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

const root = fileURLToPath(new URL("..", import.meta.url));
const binaries = join(root, "src-tauri", "binaries");
const release = process.argv.includes("--release") || (process.env.TAURI_ENV_DEBUG !== undefined && process.env.TAURI_ENV_DEBUG !== "true");

function hostTriple(): string {
  const info = execFileSync("rustc", ["-vV"], { encoding: "utf-8" });
  const host = info.split("\n").find(line => line.startsWith("host: "));
  if (!host) throw new Error("rustc -vV didn't say the host target");
  return host.slice("host: ".length).trim();
}

function build(target: string | null): string {
  const args = ["build", "-p", "vpn-worker"];
  if (release) args.push("--release");
  if (target) args.push("--target", target);
  execFileSync("cargo", args, { cwd: root, stdio: "inherit" });
  const profile = release ? "release" : "debug";
  const windows = (target ?? hostTriple()).includes("windows");
  return join(root, "target", ...(target ? [target] : []), profile, windows ? "fran-vpn.exe" : "fran-vpn");
}

async function fetchWintun(arch: string) {
  const out = join(binaries, "wintun.dll");
  if (existsSync(out)) return;
  const response = await fetch(WINTUN_URL);
  if (!response.ok) throw new Error(`Couldn't download Wintun: ${response.status} ${response.statusText}`);
  const zip = Buffer.from(await response.arrayBuffer());
  const hash = createHash("sha256").update(zip).digest("hex");
  if (hash !== WINTUN_SHA256) throw new Error(`Wintun's zip has SHA-256 ${hash}, expected ${WINTUN_SHA256}`);
  const dir = mkdtempSync(join(tmpdir(), "wintun-"));
  try {
    writeFileSync(join(dir, "wintun.zip"), zip);
    execFileSync(join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe"), ["-xf", join(dir, "wintun.zip"), "-C", dir], { stdio: "inherit" });
    copyFileSync(join(dir, "wintun", "bin", arch, "wintun.dll"), out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function main() {
  const triple = process.env.TAURI_ENV_TARGET_TRIPLE ?? hostTriple();
  mkdirSync(binaries, { recursive: true });

  if (triple === "universal-apple-darwin") {
    const arm = build("aarch64-apple-darwin");
    const intel = build("x86_64-apple-darwin");
    execFileSync("lipo", ["-create", "-output", join(binaries, `fran-vpn-${triple}`), arm, intel], { stdio: "inherit" });
    // Tauri builds the app once per architecture, and each build checks for its own copy.
    copyFileSync(arm, join(binaries, "fran-vpn-aarch64-apple-darwin"));
    copyFileSync(intel, join(binaries, "fran-vpn-x86_64-apple-darwin"));
    return;
  }

  const crossTarget = triple === hostTriple() ? null : triple;
  const built = build(crossTarget);
  const windows = triple.includes("windows");
  copyFileSync(built, join(binaries, `fran-vpn-${triple}${windows ? ".exe" : ""}`));
  if (windows) {
    await fetchWintun(triple.startsWith("aarch64") ? "arm64" : "amd64");
    // Setting up the service copies it from beside fran-vpn, also in a dev build.
    copyFileSync(join(binaries, "wintun.dll"), join(dirname(built), "wintun.dll"));
  }
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
