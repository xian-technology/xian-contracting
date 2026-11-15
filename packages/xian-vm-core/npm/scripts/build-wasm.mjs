import { dirname, delimiter } from "node:path";
import { spawnSync } from "node:child_process";

const env = { ...process.env };
const rustc = spawnSync("rustup", ["which", "rustc"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
});

if (rustc.status === 0) {
  env.PATH = `${dirname(rustc.stdout.trim())}${delimiter}${env.PATH ?? ""}`;
}

// The browser build: no LMDB (C) and no Python, only the engine over its
// in-memory store. Arguments after `--` go to cargo.
const result = spawnSync(
  "wasm-pack",
  [
    "build",
    "..",
    "--target",
    "bundler",
    "--out-dir",
    "npm/dist",
    "--out-name",
    "xian_vm_core",
    "--no-pack",
    "--features",
    "wasm",
    "--no-default-features",
    ...process.argv.slice(2),
  ],
  {
    env,
    stdio: "inherit",
  }
);

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
