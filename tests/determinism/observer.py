"""Exact, metered native observations independent of process/environment profiles.

The observer preserves contract iteration order and binary representations. Only
storage keys are sorted. Authored expectations are checked with explicit raises,
so running the campaign under ``python -O`` cannot disable its oracle.
"""

import hashlib
import json
import struct
from decimal import Decimal
from pathlib import Path

from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import decode, encode
from xian_runtime_types.time import Datetime, Timedelta

from contracting.storage.driver import Driver

DEFAULT_BUDGET = 100_000_000


def _type_name(value):
    cls = type(value)
    return f"{cls.__module__}.{cls.__qualname__}"


def _decimal_parts(value):
    parts = value.as_tuple()
    return [parts.sign, list(parts.digits), parts.exponent]


def _scalar(value):
    kind = _type_name(value)
    if value is None or type(value) in (bool, str):
        return [kind, value]
    if type(value) is int:
        # Decimal conversion limits are ambient Python settings; hexadecimal
        # remains exact and serializable for every VM-supported integer size.
        return [kind, hex(value)]
    if type(value) is float:
        return [kind, struct.pack(">d", value).hex()]
    if isinstance(value, (bytes, bytearray)):
        return [kind, value.hex()]
    return _special_scalar(value, kind)


def _special_scalar(value, kind):
    if isinstance(value, Decimal):
        return [kind, _decimal_parts(value)]
    if isinstance(value, ContractingDecimal):
        return [kind, _decimal_parts(value._d)]
    if isinstance(value, Datetime):
        return [
            kind,
            [
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
            ],
        ]
    if isinstance(value, Timedelta):
        raw = value._timedelta
        return [kind, [raw.days, raw.seconds, raw.microseconds]]
    if isinstance(value, range):
        return [kind, [value.start, value.stop, value.step]]
    return None


def encode_exact(value):
    """Encode values losslessly, including cycles/aliasing in Python containers."""
    seen = {}

    def visit(item):
        scalar = _scalar(item)
        if scalar is not None:
            return scalar
        if not isinstance(
            item, (dict, list, tuple, set, frozenset, ContractingSet, ContractingFrozenSet)
        ):
            raise TypeError(f"unsupported observation type: {_type_name(item)}")
        identity = id(item)
        if identity in seen:
            return ["reference", seen[identity]]
        reference = len(seen)
        seen[identity] = reference
        if isinstance(item, dict):
            members = [[visit(key), visit(value)] for key, value in item.items()]
        else:
            members = [visit(value) for value in item]
        return [_type_name(item), reference, members]

    return visit(value)


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _disk_state(driver):
    return [
        [key, encode_exact(driver.value_from_disk(key))] for key in sorted(driver.keys_from_disk())
    ]


def _pending_state(driver):
    return encode_exact([driver.pending_items(), driver.log_events])


def _visible_state(driver):
    return [[key, encode_exact(value)] for key, value in sorted(driver.items().items())]


def _fixed_time():
    return Datetime(2026, 11, 3, 12, 34, 56, 789012)


def _context(name, function):
    return {
        "signer": "alice",
        "caller": "alice",
        "this": name,
        "owner": "alice",
        "entry": (name, function),
        "submission_name": "submission",
        "now": _fixed_time(),
        "block_num": 17,
        "block_hash": "0123456789abcdef" * 4,
        "__input_hash": "fedcba9876543210" * 4,
        "chain_id": "determinism-local",
    }


def _artifact(driver, name):
    source = driver.get_contract_source(name)
    ir = driver.get_contract_ir(name)
    parsed = json.loads(ir)
    return {
        "name": name,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "ir_sha256": hashlib.sha256(ir.encode("utf-8")).hexdigest(),
        "ir_metadata": {
            key: value
            for key, value in parsed.items()
            if key
            in (
                "schema_version",
                "version",
                "module_name",
                "vm_profile",
                "format",
                "ir_version",
                "host_catalog_version",
            )
        },
    }


def _deploy(driver, case, name):
    from contracting.artifacts import build_contract_artifacts

    sources = list(case.get("dependencies", {}).items()) + [(name, case["source"])]
    try:
        for contract, source in sources:
            artifact = build_contract_artifacts(
                module_name=contract, source=source, vm_profile=driver.vm_profile
            )
            driver.set_contract(
                contract,
                source=artifact["source"],
                vm_ir_json=artifact["vm_ir_json"],
                owner=None if contract != name else "alice",
                timestamp=_fixed_time(),
            )
    except Exception as exc:
        raise AssertionError(f"{case['id']}: unexpected admission rejection: {exc}") from exc
    driver.commit()
    return [_artifact(driver, contract) for contract, _ in sources]


def _execute(driver, name, step):
    from xian_vm_core import execute_contract

    function = step.get("function", "probe")
    return execute_contract(
        driver=driver,
        vm_profile=driver.vm_profile,
        contract_name=name,
        function_name=function,
        kwargs=step.get("kwargs", {}),
        context=_context(name, function),
        meter=True,
        chi_budget_raw=step.get("chi_budget_raw", DEFAULT_BUDGET),
    )


def _validate_expected(output, step, label):
    expected_status = int(step.get("expected_failure", False))
    if output.status_code != expected_status:
        detail = (
            str(output.result)
            if isinstance(output.result, BaseException)
            else encode_exact(output.result)
        )
        raise AssertionError(
            f"{label}: expected status {expected_status}, got {output.status_code}: {detail}"
        )
    if "expected_result" in step:
        _require(
            encode_exact(output.result) == encode_exact(step["expected_result"]),
            f"{label}: expected result differs from exact native result",
        )
    if "expected_decimal" in step:
        expected = ContractingDecimal(step["expected_decimal"])
        _require(
            encode_exact(output.result) == encode_exact(expected),
            f"{label}: expected exact decimal {step['expected_decimal']}",
        )
    if "expected_error" in step:
        _require(
            output.status_code != 0 and step["expected_error"] in str(output.result),
            f"{label}: expected error {step['expected_error']!r}, got {output.result!r}",
        )


def _commit_success(driver, output, label):
    driver.apply_writes(output.writes)
    # Persistence intentionally canonicalizes supported wire types (for example
    # tuple values become lists). Compare against that documented codec boundary,
    # while the returned writes above retain their original exact representations.
    profile = driver.vm_profile
    expected = [
        [key, encode_exact(decode(encode(value, vm_profile=profile), vm_profile=profile))]
        for key, value in sorted(driver.items().items())
        if value is not None
    ]
    driver.commit()
    _require(_disk_state(driver) == expected, f"{label}: committed state differs from writes")


def _observe_step(driver, name, step, label):
    before = _disk_state(driver)
    pending = _pending_state(driver)
    visible = _visible_state(driver)
    output = _execute(driver, name, step)
    _validate_expected(output, step, label)
    _require(_disk_state(driver) == before, f"{label}: native execution mutated persisted state")
    _require(
        _pending_state(driver) == pending, f"{label}: native execution leaked pending state/events"
    )
    _require(_visible_state(driver) == visible, f"{label}: native execution changed visible state")
    observation = {
        "status_code": output.status_code,
        "chi_used": output.chi_used,
        "raw_cost": output.raw_cost,
        "contract_costs": encode_exact(output.contract_costs),
        "writes": encode_exact(output.writes),
        "events": encode_exact(output.events),
        "state_before": before,
    }
    if output.status_code == 0:
        observation["result"] = encode_exact(output.result)
        _commit_success(driver, output, label)
    else:
        _require(
            not output.writes and not output.events,
            f"{label}: failed execution returned writes/events",
        )
        observation["error"] = {
            "type": _type_name(output.result),
            "message": str(output.result),
            "args": encode_exact(output.result.args)
            if isinstance(output.result, BaseException)
            else encode_exact(output.result),
        }
    observation["state_after"] = _disk_state(driver)
    if output.status_code != 0:
        _require(observation["state_after"] == before, f"{label}: failed execution changed state")
    return observation


def observe_case(case, home, *, reopen=False):
    """Deploy fixed artifacts and execute authored steps with a checked native oracle.

    ``reopen`` adds cold Driver boundaries before execution and between steps;
    both modes inspect committed disk state and perform a final close/reopen check.
    Each case must use a fresh storage home; preexisting state fails closed.
    """
    home = Path(home)
    name = "determinism_" + case["id"]
    profile = case.get("vm_profile", "xian_vm_v2")
    driver = Driver(storage_home=home, vm_profile=profile)
    try:
        _require(not driver.keys_from_disk(), f"{case['id']}: expected fresh storage home")
        artifacts = _deploy(driver, case, name)
        deployed = _disk_state(driver)
        executions = []
        for index, step in enumerate(case.get("steps", [case])):
            if reopen:
                driver.close()
                driver = Driver(storage_home=home, vm_profile=profile)
            executions.append(_observe_step(driver, name, step, f"{case['id']} step {index}"))
        _require(bool(executions), f"{case['id']}: expected at least one execution")
        final = _disk_state(driver)
        driver.close()
        driver = Driver(storage_home=home, vm_profile=profile)
        _require(_disk_state(driver) == final, f"{case['id']}: state changed on reopen")
        return {
            "id": case["id"],
            "admission": "accepted",
            "artifacts": artifacts,
            "deployed_state": deployed,
            "executions": executions,
            "final_state": final,
        }
    finally:
        driver.close()
