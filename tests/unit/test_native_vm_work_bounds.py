"""Host work that grows with an argument is refused or charged before it runs.

A contract call must never make the host draw, hash or collect in proportion
to an argument it was not charged for: one such transaction would stall every
validator. The VM refuses these calls before any host work, for every host
(the Rust block host and Python's NativeVmHost), so both paths fail alike.
The timing bounds are generous for CI and still far below the unbounded work.
"""

from __future__ import annotations

import time

import pytest
from xian_runtime_types.time import Datetime

pytestmark = pytest.mark.optional_native

SOURCE = """
@export
def bits(k: int, salt: str):
    random.seed(salt)
    return random.getrandbits(k)

@export
def draws(k: int):
    random.seed()
    return len(random.choices([1, 2], k=k))

@export
def seeded(kind: str):
    salts = {
        "decimal": decimal("1.5"),
        "list": [1, 2],
        "dict": {"a": 1},
        "tuple": (1, "a"),
        "datetime": now,
        "timedelta": datetime.timedelta(days=1),
        "str": "abc",
        "int": -7,
        "bool": True,
        "none": None,
    }
    random.seed(salts[kind])
    return random.getrandbits(8)

@export
def pick(kind: str):
    random.seed()
    populations = {"dict": {"a": 1}, "list": [1, 2], "str": "ab", "set": set([1])}
    return random.choices(populations[kind], k=1)

@export
def materialize(kind: str, n: int):
    if kind == "list":
        return len(list(range(n)))
    if kind == "tuple":
        return len(tuple(range(n)))
    if kind == "set":
        return len(set(range(n)))
    if kind == "sorted":
        return len(sorted(range(n)))
    return len(list(reversed(range(n))))

@export
def hash_code(name: str, kind: str):
    return importlib.code_hash(name, kind=kind)
"""
BIG = "\n".join(
    f"@export\ndef f{i}(a: int):\n    return [a, a + 1, a * 2, 'pad{i}' * 3]\n" for i in range(120)
)
SAFE_LIMIT = 512
SEQUENCE_LIMIT = 128 * 1024


@pytest.fixture(scope="module")
def driver(tmp_path_factory):
    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path_factory.mktemp("bounds")) as driver:
        driver.set_contract_from_source("con_bounds", SOURCE, owner=None)
        driver.set_contract_from_source("con_big", BIG, owner=None)
        driver.commit()
        yield driver


def run(driver, function, input_hash="x", **kwargs):
    from tests.vm_calls import execute_contract

    context = {
        "signer": "alice",
        "caller": "alice",
        "this": "con_bounds",
        "entry": ("con_bounds", function),
        "now": Datetime(2026, 1, 2, 3, 4, 5),
        "block_num": 1,
        "block_hash": "h",
        "chain_id": "c",
        "__input_hash": input_hash,
    }
    started = time.perf_counter()
    output = execute_contract(
        driver=driver,
        contract_name="con_bounds",
        function_name=function,
        kwargs=kwargs,
        context=context,
        meter=True,
        chi_budget_raw=200_000_000,
    )
    return output, time.perf_counter() - started


def test_getrandbits_above_the_v2_boundary_fails_before_drawing(driver):
    elapsed = 0.0
    for k in (513, 520, 2**30, 2**40, 2**511):
        output, seconds = run(driver, "bits", k=k, salt="s")
        elapsed += seconds
        assert output.status_code == 1
        assert output.result == "integer exceeds the 512-bit magnitude limit"
    assert elapsed < 0.5
    # Refused whatever the draw: a 513-bit draw used to fit half the time.
    for index in range(32):
        output, _ = run(driver, "bits", input_hash=f"tx{index}", k=SAFE_LIMIT + 1, salt="s")
        assert output.status_code == 1
    output, _ = run(driver, "bits", k=SAFE_LIMIT, salt="s")
    assert output.status_code == 0
    assert 0 <= output.result < 2**SAFE_LIMIT


def test_choices_above_the_sequence_limit_fail_before_drawing(driver):
    started = time.perf_counter()
    for k in (SEQUENCE_LIMIT + 1, 2**40):
        output, _ = run(driver, "draws", k=k)
        assert output.status_code == 1
        assert output.result == "random.choices() exceeds the maximum allowed allocation size"
    assert time.perf_counter() - started < 0.5
    output, _ = run(driver, "draws", k=SEQUENCE_LIMIT)
    assert (output.status_code, output.result) == (0, SEQUENCE_LIMIT)


@pytest.mark.parametrize("kind", ["decimal", "list", "dict", "tuple", "datetime", "timedelta"])
def test_seed_salts_other_than_str_int_or_none_fail(driver, kind):
    output, _ = run(driver, "seeded", kind=kind)
    assert output.status_code == 1
    assert output.result == "random.seed() salt must be a str, int or None"


@pytest.mark.parametrize("kind", ["str", "int", "bool", "none"])
def test_str_int_bool_and_none_salts_seed(driver, kind):
    output, _ = run(driver, "seeded", kind=kind)
    assert output.status_code == 0


def test_populations_must_be_sequences_the_vm_indexes(driver):
    for kind in ("dict", "set"):
        output, _ = run(driver, "pick", kind=kind)
        assert output.status_code == 1
        assert output.result == (
            "random.choices() population must be a list, tuple, str, bytes or bytearray"
        )
    for kind in ("list", "str"):
        output, _ = run(driver, "pick", kind=kind)
        assert output.status_code == 0


@pytest.mark.parametrize("kind", ["list", "tuple", "set", "sorted", "reversed"])
def test_a_range_too_long_to_materialize_fails_without_iterating(driver, kind):
    elapsed = 0.0
    for _ in range(20):
        output, seconds = run(driver, "materialize", kind=kind, n=10**9)
        elapsed += seconds
        assert output.status_code == 1
        assert output.result == "iterable exceeds allocation limit"
    # Collecting the 131,072 items it refuses after took ~35 ms per call.
    assert elapsed < 0.35
    output, _ = run(driver, "materialize", kind=kind, n=1000)
    assert (output.status_code, output.result) == (0, 1000)


def test_code_hash_charges_the_bytes_it_hashes(driver):
    from contracting.storage.keys import SOURCE_KEY, XIAN_VM_V1_IR_KEY

    ir = driver.get(f"con_big.{XIAN_VM_V1_IR_KEY}")
    source = driver.get(f"con_big.{SOURCE_KEY}")
    small, _ = run(driver, "hash_code", name="con_missing", kind="ir")
    for kind, text in (("ir", ir), ("source", source)):
        output, _ = run(driver, "hash_code", name="con_big", kind=kind)
        assert output.status_code == 0
        # 4 raw chi per hashed byte, as hashlib.sha3 charges.
        assert output.chi_used - small.chi_used >= len(text.encode()) * 4 // 1000 - 1
