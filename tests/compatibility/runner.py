"""Typed evidence and native V2 execution for current surface checks.

Immutable historical Python observers live in historical/ and are used only by
the pinned capture scripts, never as a fallback for current execution.
"""

import json
import sys
from pathlib import Path


def encode(value):
    """Preserve types, dict key identity and iteration order in JSON evidence."""
    kind = type(value).__name__
    if value is None or type(value) in (bool, int, str):
        return [kind, value]
    if isinstance(value, dict):
        return [kind, [[encode(k), encode(v)] for k, v in value.items()]]
    if isinstance(value, (list, tuple)):
        return [kind, [encode(item) for item in value]]
    if kind in ("set", "frozenset", "ContractingSet", "ContractingFrozenSet"):
        return [kind, sorted((encode(item) for item in value), key=repr)]
    return [kind, scalar_text(value, kind)]


def scalar_text(value, kind):
    if type(value) is float or isinstance(value, (bytes, bytearray)):
        return value.hex()
    if kind == "ContractingDecimal":
        return historical_decimal_text(value)
    if kind in ("Decimal", "Datetime", "Timedelta"):
        return str(value)
    raise TypeError(f"Unrecorded baseline value type: {kind}")


def historical_decimal_text(value):
    """The spelling the pinned observers recorded: historical str() was engineering text."""
    from decimal import Decimal

    from xian_runtime_types.decimal import CONTEXT

    return Decimal(str(value)).normalize(CONTEXT).to_eng_string()


def run_case(case, storage_home, *, native=True):
    """Observe current native (V2) execution without a working-tree Python engine."""
    if native is not True:
        raise ValueError("Current compatibility observation requires native execution.")
    from contracting.storage.driver import Driver

    with Driver(storage_home=storage_home, vm_profile="xian_vm_v2") as driver:
        return observe_case(driver, case)


def execution_context(name):
    from xian_runtime_types.time import Datetime

    return {
        "signer": "alice",
        "caller": "alice",
        "this": name,
        "entry": (name, "probe"),
        "owner": "alice",
        "now": Datetime(2026, 3, 25),
        "block_num": 7,
        "block_hash": "abcd1234",
        "chain_id": "xian-test",
    }


def observe_case(driver, case):
    from tests.vm_calls import execute_contract

    name = "baseline_" + case["id"]
    try:
        for dependency, source in case.get("dependencies", {}).items():
            driver.set_contract_from_source(dependency, source, owner=None)
        driver.set_contract_from_source(name, case["source"], owner="alice")
    except Exception as exc:
        return {"admission": "rejected", "diagnostic": type(exc).__name__}
    driver.commit()
    output = execute_contract(
        driver=driver,
        contract_name=name,
        function_name="probe",
        kwargs={},
        context=execution_context(name),
        meter=False,
    )
    observation = {
        "admission": "accepted",
        "status_code": output.status_code,
        "writes": encode(output.writes),
        "events": encode(output.events),
    }
    if output.status_code == 0:
        observation["result"] = encode(output.result)
    else:
        observation["diagnostic"] = str(output.result)
        observation["exception_type"] = type(output.result).__name__
    return observation


def comparable(observation):
    """Error messages/classes are evidence, not a cross-engine string API."""
    return {k: v for k, v in observation.items() if k not in ("diagnostic", "exception_type")}


if __name__ == "__main__":
    import tempfile

    cases = json.loads(Path(sys.argv[1]).read_text())
    with tempfile.TemporaryDirectory() as directory:
        results = {case["id"]: run_case(case, Path(directory) / case["id"]) for case in cases}
    Path(sys.argv[2]).write_text(json.dumps(results, indent=2) + "\n")
