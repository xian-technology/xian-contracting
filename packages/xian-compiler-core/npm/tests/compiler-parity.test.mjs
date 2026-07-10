import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import {
  compileContractArtifactJson,
  compilerVersionJson,
  diagnoseContractJson,
} from "../dist/xian_compiler_core.js";

const fixtureDirectory = new URL("../../tests/fixtures/", import.meta.url);

async function compilerFixtures() {
  const names = (await readdir(fixtureDirectory))
    .filter((name) => name.endsWith(".json"))
    .sort();
  return Promise.all(
    names.map(async (name) => ({
      name,
      fixture: JSON.parse(await readFile(new URL(name, fixtureDirectory), "utf8")),
    })),
  );
}

for (const { name, fixture } of await compilerFixtures()) {
  test(`WASM binding matches ${name}`, () => {
    const diagnostics = JSON.parse(
      diagnoseContractJson(
        fixture.module_name,
        fixture.input_source,
        JSON.stringify({ lint: true, vm_profile: fixture.vm_profile }),
      ),
    );
    assert.deepEqual(diagnostics, fixture.diagnostics);

    if (fixture.expected.accepted) {
      const artifact = JSON.parse(
        compileContractArtifactJson(
          fixture.module_name,
          fixture.input_source,
          JSON.stringify({ lint: true, vm_profile: fixture.vm_profile }),
        ),
      );
      assert.deepEqual(artifact, fixture.artifact);
    } else {
      assert.throws(() =>
        compileContractArtifactJson(
          fixture.module_name,
          fixture.input_source,
          JSON.stringify({ lint: true, vm_profile: fixture.vm_profile }),
        ),
      );
    }
  });
}

const limits = JSON.parse(compilerVersionJson()).limits;

function diagnosticCode(source) {
  const diagnostics = JSON.parse(diagnoseContractJson("con_limit", source));
  assert.equal(diagnostics.length, 1);
  return diagnostics[0].code;
}

test("WASM binding enforces source byte limit", () => {
  assert.equal(
    diagnosticCode("a".repeat(limits.max_source_bytes + 1)),
    "xian.limit.source_bytes",
  );
});

test("WASM binding enforces total token limit", () => {
  const source = "a=0\n".repeat(Math.floor(limits.max_tokens / 4) + 1);
  assert.equal(diagnosticCode(source), "xian.limit.tokens");
});

test("WASM binding enforces logical-line token limit", () => {
  const source = `value = ${"not ".repeat(limits.max_logical_line_tokens)}True\n`;
  assert.equal(diagnosticCode(source), "xian.limit.logical_line_tokens");
});

test("WASM binding enforces syntax node limit", () => {
  const source = "a=0\n".repeat(Math.floor(limits.max_syntax_nodes / 3) + 1);
  assert.equal(diagnosticCode(source), "xian.limit.syntax_nodes");
});

test("WASM binding enforces syntax depth limit", () => {
  const source = `@export\ndef value():\n    return ${"not ".repeat(limits.max_syntax_depth)}True\n`;
  assert.equal(diagnosticCode(source), "xian.limit.syntax_depth");
});
