# Packages

This folder contains smaller publishable packages shared by the Xian runtime
and node stack. They stay separate so the default `xian-tech-contracting`
install remains pure Python and easy to install.

## Contents

- `xian-runtime-types/`: deterministic shared value types and encoding
- `xian-accounts/`: shared signing and account primitives
- `xian-fastpath-core/`: optional native fast paths for transaction admission,
  published as `xian-tech-fastpath-core`
- `xian-native-tracer/`: optional native tracer backend, published as
  `xian-tech-native-tracer`
- `xian-vm-core/`: native `xian_ir_v1` validation and early VM execution work,
  published as `xian-tech-vm-core`
- `xian-zk/`: native Groth16 BN254 verification and shielded-note proving
  toolkit, published as `xian-tech-zk`

## Notes

Keep these packages small and purpose-built. Shared code belongs here only when
it has a clear runtime/node boundary and an independent package surface.
