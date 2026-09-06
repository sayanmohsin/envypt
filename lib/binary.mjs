import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const platformMap = {
  "darwin/arm64": "darwin-arm64",
  "darwin/x64": "darwin-x64",
  "linux/x64": "linux-x64",
  "linux/arm64": "linux-arm64",
  "win32/x64": "win32-x64",
};

export function binaryPath() {
  if (process.env.OPEN_ENVAULT_BIN || process.env.ENVYPT_BIN) {
    return resolve(process.env.OPEN_ENVAULT_BIN ?? process.env.ENVYPT_BIN);
  }
  const key = `${process.platform}/${process.arch}`;
  const dir = platformMap[key];
  if (!dir) {
    throw new Error(`open-envault: unsupported platform ${key}`);
  }
  const exe = process.platform === "win32" ? "open-envault.exe" : "open-envault";
  const pkgRoot = dirname(fileURLToPath(import.meta.url));
  const prebuild = join(pkgRoot, "..", "prebuilds", dir, exe);
  if (existsSync(prebuild)) return prebuild;
  const candidates = [
    join(pkgRoot, "..", "target", "debug", exe),
    join(pkgRoot, "..", "target", "release", exe),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  throw new Error(`open-envault: binary not found for ${key}. Tried ${prebuild}`);
}
