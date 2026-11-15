import { mkdirSync, writeFileSync } from "node:fs";

const distUrl = new URL("../dist/", import.meta.url);

mkdirSync(distUrl, { recursive: true });
writeFileSync(
  new URL(".npmignore", distUrl),
  "# Keep wasm-pack output publishable from the parent npm package.\n"
);
