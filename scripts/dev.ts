// Tauri's beforeDevCommand. Vite starts right away, so Tauri doesn't give up waiting for it while fran-vpn builds,
// and the app's own cargo build waits on the target/ lock until the worker's is done.

import { ChildProcess, spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

const vite = spawn(process.execPath, [join(root, "node_modules", "vite", "bin", "vite.js")], { cwd: root, stdio: "inherit" });
const worker = spawn(process.execPath, [join(root, "scripts", "vpn-worker.ts")], { cwd: root, stdio: "inherit" });

function stop(code: number) {
  for (const child of [vite, worker] as ChildProcess[]) {
    if (child.exitCode === null) child.kill();
  }
  process.exit(code);
}

worker.on("exit", code => {
  if (code !== 0) stop(code ?? 1);
});
vite.on("exit", code => stop(code ?? 0));
process.on("SIGINT", () => stop(0));
process.on("SIGTERM", () => stop(0));
