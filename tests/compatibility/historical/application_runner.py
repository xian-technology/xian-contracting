"""Installed-runtime application observer; also runs unchanged in pinned Python."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

try:
    from .application_expectations import expected_current
    from .runner import comparable, encode
except ImportError:  # standalone historical/installed-runtime invocation
    from application_expectations import expected_current
    from runner import comparable, encode

FIXTURES = Path(__file__).resolve().parent / "applications"
DEPLOYER = """@export
def deploy(name: str, code: str):
    __Contract().submit(name=name, code=code)
"""
# Runtime/compiler records are not application state. Keep this explicit: an
# arbitrary application variable beginning '__' must not disappear from evidence.
METADATA = {
    "__code__",
    "__compiled__",
    "__owner__",
    "__submitted__",
    "__developer__",
    "__deployer__",
    "__initiator__",
    "__vm_ir__",
    "__vm_ir_json__",
    "__vm_artifact__",
    "__vm_version__",
    "__type__",
    "__source__",
    "__xian_ir_v1__",
    "__author__",
}


def fixtures():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    sources = {}
    for item in manifest["sources"]:
        data = (FIXTURES / item["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Pinned source digest mismatch: " + item["id"])
        sources[item["id"]] = data.decode()
    return manifest, sources, json.loads((FIXTURES / "sequences.json").read_text())


def data_state(driver, names):
    result = {}
    for name in names:
        for key, value in driver.items(name + ".").items():
            if key.split(".", 1)[1] not in METADATA:
                result[key] = value
    return {key: result[key] for key in sorted(result)}


def context_for(step):
    from xian_runtime_types.time import Datetime

    name, function = step["contract"], step["function"]
    sender = step.get("sender", "alice")
    return dict(
        signer=sender,
        caller=sender,
        this=name,
        owner=None,
        entry=(name, function),
        now=Datetime(*step.get("now", [2025, 10, 27])),
        block_num=1,
        block_hash="application-corpus",
        chain_id="local-corpus",
    )


def arguments(value):
    if isinstance(value, list):
        return [arguments(item) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$datetime"}:
            from xian_runtime_types.time import Datetime

            return Datetime(*value["$datetime"])
        return {key: arguments(item) for key, item in value.items()}
    return value


def invoke(driver, step, engine):
    context = context_for(step)
    kwargs = arguments(step.get("kwargs", {}))
    if engine in ("native", "native-metered"):
        from xian_vm_core import execute_contract

        result = execute_contract(
            driver=driver,
            vm_profile="xian_vm_v1",
            contract_name=step["contract"],
            function_name=step["function"],
            kwargs=kwargs,
            context=context,
            meter=engine == "native-metered",
            chi_budget_raw=100_000_000 if engine == "native-metered" else 0,
        )
        return {key: getattr(result, key) for key in ("status_code", "result", "writes", "events")}
    from contracting.execution.executor import Executor

    return Executor(driver=driver, metering=False).execute(
        sender=context["signer"],
        contract_name=step["contract"],
        function_name=step["function"],
        kwargs=kwargs,
        environment=context,
        metering=False,
    )


def validate_outcome(step, output):
    status = output["status_code"]
    expected = step.get("error")
    if bool(status) != bool(expected):
        raise AssertionError(f"{step['id']}: unexpected outcome {output['result']!r}")
    if expected and expected not in str(output["result"]):
        raise AssertionError(f"{step['id']}: wrong business failure {output['result']!r}")


def observe(driver, step, engine, names):
    before = encode(dict(sorted(driver.items().items())))
    output = invoke(driver, step, engine)
    status = output["status_code"]
    validate_outcome(step, output)
    writes = {
        key: value
        for key, value in output["writes"].items()
        if key.split(".", 1)[-1] not in METADATA
    }
    result = dict(
        id=step["id"],
        status_code=status,
        writes=encode(dict(sorted(writes.items()))),
        events=encode(output["events"]),
    )
    if status:
        result.update(
            diagnostic=str(output["result"]), exception_type=type(output["result"]).__name__
        )
        if output["writes"] or output["events"]:
            raise AssertionError(f"{step['id']}: failure leaked effects")
        if encode(dict(sorted(driver.items().items()))) != before:
            raise AssertionError(f"{step['id']}: failed execution changed state")
        driver.rollback()
    else:
        result["result"] = encode(output["result"])
        for key, value in output["writes"].items():
            driver.set(key, value)
        driver.commit()
    result["state"] = encode(data_state(driver, names))
    return result


def install_bootstrap(driver, engine):
    from contracting.stdlib.env import gather

    deployer = DEPLOYER.replace("__Contract", "Contract") if "Contract" in gather() else DEPLOYER
    if engine in ("native", "native-metered"):
        from contracting.artifacts import build_contract_artifacts

        artifact = build_contract_artifacts(
            module_name="submission", source=deployer, lint=False, vm_profile="xian_vm_v1"
        )
        driver.set_contract(
            "submission", source=artifact["source"], vm_ir_json=artifact["vm_ir_json"]
        )
    else:
        driver.set_contract_from_source("submission", deployer, owner=None, lint=False)


def run_sequence(sequence, sources, home, engine):
    from contracting.storage.driver import Driver

    # Only the pre-VM oracle installation has no profile argument.
    profile = {} if engine == "historical-python" else {"vm_profile": "xian_vm_v1"}
    driver = Driver(storage_home=home, **profile)
    try:
        install_bootstrap(driver, engine)
        driver.commit()
    finally:
        driver._store.close()
    names = [deployment["name"] for deployment in sequence["deployments"]]
    steps = [
        dict(
            id="deploy_" + item["name"],
            contract="submission",
            function="deploy",
            kwargs=dict(name=item["name"], code=sources[item["source"]]),
        )
        for item in sequence["deployments"]
    ] + sequence["steps"]
    observations = []
    previous = None
    for step in steps:
        driver = Driver(storage_home=home, **profile)
        try:
            if previous is not None and encode(data_state(driver, names)) != previous:
                raise AssertionError("Persisted state differs after reopening storage")
            observation = observe(driver, step, engine, names)
            previous = observation["state"]
            observations.append(observation)
        finally:
            driver._store.close()
    driver = Driver(storage_home=home, **profile)
    try:
        if encode(data_state(driver, names)) != previous:
            raise AssertionError("Final persisted state differs after reopening storage")
    finally:
        driver._store.close()
    return observations


def run_all(engine, selected=None):
    _, sources, sequences = fixtures()
    if selected is not None and selected not in {item["id"] for item in sequences}:
        raise ValueError("Unknown application sequence: " + selected)
    with tempfile.TemporaryDirectory(prefix="xian-applications-") as directory:
        return {
            sequence["id"]: run_sequence(
                sequence, sources, Path(directory) / sequence["id"], engine
            )
            for sequence in sequences
            if selected is None or sequence["id"] == selected
        }


def comparison(observations):
    return {name: [comparable(step) for step in steps] for name, steps in observations.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine", choices=["historical-python", "python", "native", "native-metered"], default="native"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--sequence")
    options = parser.parse_args()
    observations = run_all(options.engine, options.sequence)
    if options.output:
        options.output.write_text(json.dumps(observations, indent=2) + "\n")
    if options.check:
        baseline = json.loads((FIXTURES / "legacy_baseline.json").read_text())["observations"]
        baseline = {key: baseline[key] for key in observations}
        deviations = json.loads((FIXTURES / "current_policy_deviations.json").read_text())
        baseline, count = expected_current(baseline, deviations)
        print(f"Reviewed policy differences: {count} exact fields (historical baseline retained)")
        if comparison(observations) != comparison(baseline):
            raise AssertionError("Application observations differ; inspect --output evidence")
    print(
        f"{len(observations)} applications, {sum(map(len, observations.values()))} observations executed ({options.engine})"
    )


if __name__ == "__main__":
    main()
