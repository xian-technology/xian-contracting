"""Runs unchanged under both the historical installation and today's runtime.

Keep imports of Contracting inside run_case: snapshot encoding must not select
the current runtime when this file is executed by the isolated legacy Python.
"""

import json
from pathlib import Path
import sys


def encode(value):
    """Preserve types, dict key identity and iteration order in JSON evidence."""
    kind = type(value).__name__
    if value is None or type(value) in (bool, int, str):
        return [kind, value]
    if type(value) is float:
        return [kind, value.hex()]
    if isinstance(value, (bytes, bytearray)):
        return [kind, value.hex()]
    if isinstance(value, dict):
        return [kind, [[encode(k), encode(v)] for k, v in value.items()]]
    if isinstance(value, (list, tuple)):
        return [kind, [encode(item) for item in value]]
    if kind in ("set", "frozenset", "ContractingSet", "ContractingFrozenSet"):
        return [kind, sorted((encode(item) for item in value), key=repr)]
    if kind in ("ContractingDecimal", "Decimal", "Datetime", "Timedelta"):
        return [kind, str(value)]
    raise TypeError(f"Unrecorded baseline value type: {kind}")


def run_case(case, storage_home, *, native=False):
    from contracting.execution.executor import Executor
    from contracting.storage.driver import Driver
    from xian_runtime_types.time import Datetime

    driver = Driver(storage_home=storage_home)
    name = "baseline_" + case["id"]
    try:
        for dependency, source in case.get("dependencies", {}).items():
            driver.set_contract_from_source(dependency, source, owner=None)
        driver.set_contract_from_source(name, case["source"], owner="alice")
    except Exception as exc:
        return {"admission": "rejected", "diagnostic": type(exc).__name__}
    driver.commit()
    context = {
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
    if native:
        import xian_vm_core

        result = xian_vm_core.execute_contract(
            driver=driver,
            contract_name=name,
            function_name="probe",
            kwargs={},
            context=context,
            meter=False,
        )
        output = {
            key: getattr(result, key)
            for key in (
                "status_code",
                "result",
                "writes",
                "events",
            )
        }
    else:
        output = Executor(driver=driver, metering=False).execute(
            sender="alice",
            contract_name=name,
            function_name="probe",
            kwargs={},
            environment=context,
            metering=False,
        )
    observation = {
        "admission": "accepted",
        "status_code": output["status_code"],
        "writes": encode(output["writes"]),
        "events": encode(output["events"]),
    }
    if output["status_code"] == 0:
        observation["result"] = encode(output["result"])
    else:
        observation["diagnostic"] = str(output["result"])
        observation["exception_type"] = type(output["result"]).__name__
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
