# @xian-tech/compiler

WASM bindings for `xian-compiler-core`.

```bash
npm run build
```

The generated package exposes JSON-string APIs for diagnostics
(`diagnoseContractJson`), normalization (`normalizeSource`), IR lowering
(`lowerSourceToIrJson`), artifact compilation (`compileContractArtifactJson`),
the deploy pair of normalized source and canonical IR
(`compileContractSourceJson`), artifact validation
(`validateContractArtifactJson(moduleName, artifactJson, inputSource?,
vmProfile?)`), compiler version metadata (`compilerVersionJson`), and the Xian
VM host catalog (`hostSurfaceJson`). They run the same Rust code as the Python
package `xian-tech-compiler-core`, so artifacts are byte-identical across both.

Primary browser/JS entrypoint:

```ts
import { compileContractArtifactJson } from "@xian-tech/compiler";

const artifacts = JSON.parse(
  compileContractArtifactJson(
    "con_counter",
    source,
    JSON.stringify({ lint: true })
  )
);
```

The omitted compiler profile is `xian_vm_v2`. Supply `vm_profile: "xian_vm_v1"` in options JSON to reproduce V1 artifacts.
