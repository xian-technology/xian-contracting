import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { VmChain, canonicalDecimal, runtimeInfo } from "../dist/xian_vm_core.js";

const vectors = new URL("../../tests/vectors/sandbox/", import.meta.url);
const read = (name) => readFile(new URL(name, vectors), "utf8");

const environment = {
  now: { __time__: [2026, 11, 15, 12, 0, 0, 0] },
  block_num: 7,
  chain_id: "xian-sandbox-1",
};

async function deployed() {
  const chain = new VmChain(JSON.stringify({ environment }));
  const outcome = JSON.parse(
    chain.deploy(
      JSON.stringify({
        sender: "alice",
        name: "con_token",
        source: await read("con_token.py"),
        constructor_args: { supply: 500 },
        environment,
      }),
    ),
  );
  assert.equal(outcome.status, 0, outcome.error);
  return chain;
}

function call(chain, fn, kwargs, extra = {}) {
  const request = { sender: "alice", contract: "con_token", function: fn, kwargs, environment, ...extra };
  return JSON.parse(chain.call(JSON.stringify(request)));
}

// The same scenario as the LMDB backend (xian-contracting
// tests/integration/test_vm_sandbox_parity.py) and vm-core's Rust test.
test("the WebAssembly build matches the LMDB backend byte for byte", async () => {
  const scenario = JSON.parse(await read("scenario.json"));
  const chain = new VmChain(JSON.stringify(scenario.create));
  const lines = [];
  for (const step of scenario.steps) {
    const [[kind, original]] = Object.entries(step);
    const request = { ...original };
    if (request.source_file !== undefined) {
      request.source = await read(request.source_file);
      delete request.source_file;
    }
    lines.push(kind === "deploy" ? chain.deploy(JSON.stringify(request)) : chain.call(JSON.stringify(request)));
  }
  lines.push(chain.exportState(), chain.stateRoot());
  assert.equal(lines.join("\n") + "\n", await read("transcript.txt"));
  chain.free();
});

test("a call reports its result, writes and events as wire text", async () => {
  const chain = await deployed();
  const outcome = call(chain, "transfer", { amount: { __fixed__: "1.5" }, to: "bob" });
  assert.equal(outcome.status, 0);
  assert.equal(outcome.result, '{"__fixed__":"1.5"}');
  assert.deepEqual(outcome.writes[1], ["con_token.balances:bob", '{"__fixed__":"1.5"}']);
  assert.equal(outcome.events[0].data, '{"amount":{"__fixed__":"1.5"}}');
  assert.equal(chain.get("con_token.balances:bob"), '{"__fixed__":"1.5"}');
  assert.equal(chain.get("con_token.balances:nobody"), undefined);
});

test("a JS float is refused, as the node refuses it", async () => {
  const chain = await deployed();
  assert.throws(() => call(chain, "add", { a: 0.1, b: 0.2 }), /arguments the VM does not take/);
  const exact = call(chain, "add", { a: { __fixed__: "0.1" }, b: { __fixed__: "0.2" } });
  assert.equal(exact.result, '{"__fixed__":"0.3"}');
});

test("a failed call reports its message and commits nothing", async () => {
  const chain = await deployed();
  const before = chain.exportState();
  const outcome = call(chain, "transfer", { amount: 501, to: "bob" });
  assert.equal(outcome.status, 1);
  assert.equal(outcome.error, "Insufficient balance.");
  assert.equal(chain.exportState(), before);
});

test("snapshots round-trip as text and bytes; clones are independent", async () => {
  const chain = await deployed();
  const snapshot = chain.exportState();
  assert.equal(VmChain.importState(snapshot).exportState(), snapshot);
  assert.equal(VmChain.importStateBytes(chain.exportStateBytes()).stateRoot(), chain.stateRoot());
  const copy = chain.clone();
  call(copy, "transfer", { amount: 5, to: "bob" });
  assert.equal(chain.exportState(), snapshot);
  assert.notEqual(copy.exportState(), snapshot);
  assert.throws(() => VmChain.importState('{"format":"xian-vm-state/1","entries":[["a","1.5"]]}'), /snapshot value/);
});

test("contract metadata gives the call forms", async () => {
  const chain = await deployed();
  assert.deepEqual(JSON.parse(chain.contracts()), ["con_token", "submission"]);
  const info = JSON.parse(chain.contract("con_token"));
  assert.equal(info.construct.name, "seed");
  assert.deepEqual(info.methods[0].arguments.map((argument) => argument.name), ["amount", "to"]);
  assert.equal(chain.contract("con_missing"), undefined);
  chain.setValue("con_token.metadata:note", '"hi"');
  assert.equal(chain.get("con_token.metadata:note"), '"hi"');
  chain.setValue("con_token.metadata:note");
  assert.equal(chain.get("con_token.metadata:note"), undefined);
  chain.removeContract("con_token");
  assert.deepEqual(JSON.parse(chain.items("con_token.")), []);
});

test("helpers: canonical decimals and runtime info", () => {
  assert.equal(canonicalDecimal("1.50"), "1.5");
  assert.throws(() => canonicalDecimal("abc"));
  assert.equal(JSON.parse(runtimeInfo()).execution_revision, "xvm-execution-14");
});
