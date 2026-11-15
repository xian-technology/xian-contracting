# @xian-tech/vm

The Xian VM (`xian-vm-core`, the node's only transaction engine) compiled to
WebAssembly, with an in-memory store in place of LMDB. A `VmChain` deploys and
calls contracts fully client-side: every call runs exactly the code a node runs
for one transaction (`execute_tx`), and contracts are compiled inside the VM by
the linked compiler, as `submission.submit_contract` does on chain.

```bash
npm run build   # wasm-pack build --target bundler (needs the wasm32-unknown-unknown target)
npm test        # build, then node --test (Node >= 24)
```

Arguments after `--` go to cargo (`node scripts/build-wasm.mjs --ignore-rust-version`).
The bundler target loads with webpack's `asyncWebAssembly` (Next.js) or
`vite-plugin-wasm`.

```ts
import { VmChain } from "@xian-tech/vm";
import type { TxOutcome } from "@xian-tech/vm/types";

const environment = { now: { __time__: [2026, 11, 15, 12, 0, 0] }, chain_id: "local" };
const chain = new VmChain(JSON.stringify({ environment }));
chain.deploy(JSON.stringify({ sender: "alice", name: "con_token", source, environment }));
const outcome: TxOutcome = JSON.parse(
  chain.call(
    JSON.stringify({
      sender: "alice",
      contract: "con_token",
      function: "transfer",
      kwargs: { amount: { __fixed__: "1.5" }, to: "bob" },
      environment,
    }),
  ),
);
```

## API

`VmChain` (all requests and results are JSON strings; shapes in `types.d.ts`):

| method | |
| --- | --- |
| `new VmChain(options?)` | a chain holding the `submission` contract (`CreateOptions`) |
| `clone()` | an independent copy |
| `exportState()` / `exportStateBytes()` | the committed state (`StateSnapshot`, keys in byte order) |
| `VmChain.importState(text)` / `importStateBytes(bytes)` | a chain from a snapshot; every key and value is checked |
| `deploy(request)` | `DeployRequest` -> `TxOutcome` (`submission.submit_contract`) |
| `call(request)` | `CallRequest` -> `TxOutcome` |
| `get(key)` | the wire JSON text at a full key, or `undefined` |
| `items(prefix, limit?)` | `[[key, wireText], ...]` in key order |
| `setValue(key, wireText?)` | store a value, or delete the key |
| `removeContract(name)` | delete every key of a contract |
| `contracts()` / `contract(name)` | names; `ContractInfo` (source, IR, exported functions and their arguments) |
| `stateRoot()` | hex state root over every key not starting with `__` |

Functions: `runtimeInfo()` (engine versions), `canonicalDecimal(text)`.

A malformed request or snapshot throws; a transaction that fails returns a
`TxOutcome` with `status` 1. Without metering there is no step limit.

## Values

Values use the node's wire format (the transaction and stored-value encoding):
safe integers as JSON numbers, larger ints as `{"__big_int__": "..."}`,
decimals as `{"__fixed__": "1.5"}` (canonical text), datetimes as
`{"__time__": [y, m, d, h, mi, s, us]}`, timedeltas as `{"__delta__": [days, seconds]}`,
bytes as `{"__bytes__": "hex"}`, sets in the `xian-set-1` codec. Request
arguments are canonicalized and decoded strictly, as a signed transaction is:
a JS float is refused. Results carry every value as wire JSON *text*; a value
the wire format cannot carry appears as `{"__repr__": "..."}`.

## License

MIT. The browser build contains no LMDB code (the node build's vendored LMDB
is OLDAP-2.8 and is not part of this package).
