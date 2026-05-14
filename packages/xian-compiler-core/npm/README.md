# @xian-tech/compiler

WASM bindings for `xian-compiler-core`.

```bash
npm run build
```

The generated package exposes JSON-string APIs for diagnostics, normalization,
IR lowering, artifact compilation, artifact validation, compiler version
metadata, and the Xian VM host catalog.

Primary browser/JS entrypoint:

```ts
import { compileContractArtifactJson } from "@xian-tech/compiler";

const artifacts = JSON.parse(
  compileContractArtifactJson(
    "con_counter",
    source,
    JSON.stringify({ lint: true, vm_profile: "xian_vm_v1" })
  )
);
```
