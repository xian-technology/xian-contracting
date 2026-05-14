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

const result = spawnSync(
  "wasm-pack",
  [
    "build",
    "..",
    "--target",
    "bundler",
    "--out-dir",
    "npm/dist",
    "--features",
    "wasm",
    "--no-default-features",
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
