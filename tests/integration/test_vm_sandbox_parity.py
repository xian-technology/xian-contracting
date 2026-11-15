"""The browser build's in-memory chain runs exactly what the node runs.

The scenario in ``packages/xian-vm-core/tests/vectors/sandbox`` is executed
here the node's way: genesis installs the submission contract with
``Driver.set_contract`` on LMDB, and every step runs through
``xian_vm_core.execute_tx`` over the driver's LMDB environment and block
overlay, committed by the driver. The transcript (each outcome in the
package's ``TxOutcome`` JSON, the exported state and its state root) must
equal ``transcript.txt`` byte for byte; vm-core's Rust test and the npm
package's test (the WebAssembly build) run the same scenario over the
in-memory store and compare with the same file.

Run this module as a script to rewrite the transcript:
``uv run python -m tests.integration.test_vm_sandbox_parity``.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from xian_runtime_types.encoding import decode
from xian_vm_core import StateRootTree, stored_value_bytes
from xian_vm_core._native import execute_tx

from contracting.storage.driver import Driver

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "packages" / "xian-vm-core" / "tests" / "vectors" / "sandbox"
SUBMISSION = ROOT / "src" / "contracting" / "contracts" / "submission_source.s.py"
EXECUTION_POLICY_KEY = "__execution_policy"


def _json(value) -> str:
    """JSON text as the Rust writer emits it (no spaces, UTF-8 kept)."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _wire(value) -> str:
    stored = stored_value_bytes(value)
    return "null" if stored is None else stored.decode()


def _wire_value(json_value):
    """A wire value as the node decodes one from a signed transaction."""
    return decode(json.dumps(json_value, sort_keys=True, separators=(",", ":")))


def _context(sender, contract, function, kwargs, environment):
    environment = environment or {}
    name = kwargs.get("name") if contract == "submission" else None
    return {
        "this": contract,
        "caller": sender,
        "signer": sender,
        "entry": (contract, function),
        "submission_name": name if isinstance(name, str) else None,
        "now": _wire_value(environment["now"]) if "now" in environment else None,
        "block_num": _wire_value(environment.get("block_num", -1)),
        "block_hash": environment.get("block_hash"),
        "chain_id": environment.get("chain_id"),
        "__input_hash": environment.get("input_hash"),
    }


def _call_of(kind: str, request: dict) -> dict:
    if kind == "call":
        return request
    kwargs = {"name": request["name"], "code": request["source"]}
    if request.get("owner") is not None:
        kwargs["owner"] = request["owner"]
    kwargs["constructor_args"] = request.get("constructor_args", {})
    return {
        **{key: value for key, value in request.items() if key not in ("name", "source")},
        "contract": "submission",
        "function": "submit_contract",
        "kwargs": kwargs,
    }


def _error(outcome) -> str | None:
    if outcome["status"] == 0:
        return None
    exception = outcome["exception"]
    if exception is not None and len(exception[1]) == 1 and isinstance(exception[1][0], str):
        return exception[1][0]
    return outcome["result"]


def _outcome_json(outcome) -> str:
    exception = outcome["exception"]
    events = [
        "{"
        + ",".join(
            [
                f'"contract":{_json(event["contract"])}',
                f'"event":{_json(event["event"])}',
                f'"signer":{_json(_wire(event["signer"]))}',
                f'"caller":{_json(_wire(event["caller"]))}',
                f'"data_indexed":{_json(_wire(event["data_indexed"]))}',
                f'"data":{_json(_wire(event["data"]))}',
            ]
        )
        + "}"
        for event in outcome["events"]
    ]
    writes = [
        f"[{_json(key)},{'null' if value is None else _json(_wire(value))}]"
        for key, value in outcome["writes"]
    ]
    costs = ",".join(f"{_json(name)}:{cost}" for name, cost in outcome["contract_costs"].items())
    exception_json = (
        "null"
        if exception is None
        else f'{{"name":{_json(exception[0])},"args":{_json([_wire(arg) for arg in exception[1]])}}}'
    )
    error = _error(outcome)
    fields = [
        f'"status":{outcome["status"]}',
        f'"result":{_json(_wire(outcome["result"]))}',
        f'"error":{"null" if error is None else _json(error)}',
        f'"exception":{exception_json}',
        f'"chi_used":{outcome["chi_used"]}',
        f'"writes":[{",".join(writes)}]',
        f'"events":[{",".join(events)}]',
        f'"contract_costs":{{{costs}}}',
        f'"unprepared":{"true" if outcome["unprepared"] else "false"}',
    ]
    return "{" + ",".join(fields) + "}"


def _run(driver: Driver, kind: str, request: dict) -> str:
    call = _call_of(kind, request)
    sender = call["sender"]
    kwargs = _wire_value(call.get("kwargs", {}))
    environment, overlay = driver.committed_storage()
    staged = overlay if call.get("commit", True) else overlay.snapshot()
    outcome, reason = execute_tx(
        environment,
        staged,
        sender=sender,
        contract=call["contract"],
        function=call["function"],
        kwargs=kwargs,
        context=_context(sender, call["contract"], call["function"], kwargs, call["environment"]),
        chi_budget=call.get("chi_budget", 0),
        transaction_size_bytes=call.get("transaction_size_bytes", 0),
        meter_execution=call.get("metering", True),
        charge_fees=call.get("charge_fees", False),
        protected_keys=[EXECUTION_POLICY_KEY],
        zk_enabled_without_state=True,
    )
    assert reason is None, reason
    driver.commit()
    return _outcome_json(outcome)


def _export(environment) -> str:
    entries = [
        f"[{_json(key.decode())},{_json(value.decode())}]" for key, value in environment.items(b"")
    ]
    return f'{{"format":"xian-vm-state/1","entries":[{",".join(entries)}]}}'


def lmdb_transcript(storage_home: Path) -> str:
    scenario = json.loads((SCENARIO / "scenario.json").read_text(encoding="utf-8"))
    driver = Driver(storage_home=storage_home)
    try:
        now = scenario["create"]["environment"]["now"]
        driver.set_contract(
            "submission",
            source=SUBMISSION.read_text(encoding="utf-8"),
            timestamp=_wire_value(now),
        )
        driver.commit()
        lines = []
        for step in scenario["steps"]:
            ((kind, request),) = step.items()
            request = dict(request)
            source_file = request.pop("source_file", None)
            if source_file is not None:
                request["source"] = (SCENARIO / source_file).read_text(encoding="utf-8")
            lines.append(_run(driver, kind, request))
        environment, _overlay = driver.committed_storage()
        lines.append(_export(environment))
        lines.append(StateRootTree.from_storage(environment, [], []).root_hash.hex())
        return "\n".join(lines) + "\n"
    finally:
        driver.close()


def test_the_lmdb_backend_writes_the_shared_transcript(tmp_path):
    golden = (SCENARIO / "transcript.txt").read_text(encoding="utf-8")
    assert lmdb_transcript(tmp_path / "state") == golden


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as home:
        (SCENARIO / "transcript.txt").write_text(lmdb_transcript(Path(home)), encoding="utf-8")
    sys.exit(0)
