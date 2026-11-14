"""The block host's random syscalls (vm-core ``block_host/random.rs``).

This fuzz sends random syscalls as the VM sends them. Until increment 9 of
the single-engine plan every call Rust serves was compared with the Python
random bridge (same value after the V2 boundary, or the same exception with
the same text); the outcomes were frozen then (``FIXTURE``) and Rust must
keep reproducing them. Execution revision 14 refuses the documented other
cases (other argument, population or context types, call shapes that do not
bind) with a ``TypeError`` of its own. The VM refuses calls above its work
bounds (``interpreter::random_bounds``) before the host runs them;
``vm_bound`` models that check for the generator.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import pytest
from xian_runtime_types.decimal import ContractingDecimal


pytestmark = pytest.mark.optional_native

native = pytest.importorskip("xian_vm_core._native")

SEQUENCE_LIMIT = 128 * 1024
SEQUENCES = (list, tuple, str, bytes, bytearray)
# Rust's outcomes of each fuzz case (16-digit digest of the whole sequence,
# outcome_digest), frozen where every served call matched the Python bridge
# before it was deleted.
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "random_syscall_outcomes.json"


def outcome_digest(outcome) -> str:
    text = json.dumps(outcome, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def frozen_outcomes() -> dict:
    return json.loads(FIXTURE.read_text())


MISSING = object()


def _population(function, value):
    if value("items") is MISSING or isinstance(value("items"), SEQUENCES):
        return None
    return f"random.{function}() population must be a list, tuple, str, bytes or bytearray"


def _salt(value):
    salt = value("aux_salt")
    if salt is MISSING or salt is None or isinstance(salt, (str, int)):
        return None
    return "random.seed() salt must be a str, int or None"


def _bits(value):
    if type(value("k")) is int and value("k") > 512:
        return "integer exceeds the 512-bit magnitude limit"
    return None


def _choices(value):
    refused = _population("choices", value)
    if refused is None and type(value("k")) is int and value("k") > SEQUENCE_LIMIT:
        refused = "random.choices() exceeds the maximum allowed allocation size"
    return refused


# Parameters and rule of each bounded call (interpreter::random_bounds).
BOUNDED = {
    "random.getrandbits": (("k",), _bits),
    "random.choices": (("items", "k"), _choices),
    "random.choice": (("items",), lambda value: _population("choice", value)),
    "random.seed": (("aux_salt",), _salt),
}


def vm_bound(syscall_id, args, kwargs):
    """The VM's refusal of a call above the V2 work bounds, if any."""
    if syscall_id not in BOUNDED:
        return None
    params, rule = BOUNDED[syscall_id]
    if len(args) > len(params) or not set(kwargs) <= set(params[len(args) :]):
        return None

    def value(name):
        position = params.index(name)
        return args[position] if position < len(args) else kwargs.get(name, MISSING)

    return rule(value)


class Calls:
    """Random syscalls as the VM issues them, each marked served or not."""

    def __init__(self, rng: random.Random, refusals: int):
        self.rng = rng
        self.calls = []
        self.served = []
        # A refusal ends the comparison: at most this many per sequence.
        self.refusals = refusals

    def add(self, syscall, args=(), kwargs=None, *, served=True):
        # The VM's bounds refuse a call before the host would.
        served = served or vm_bound(f"random.{syscall}", list(args), dict(kwargs or {})) is not None
        if not served:
            if not self.refusals:
                return
            self.refusals -= 1
        self.calls.append((f"random.{syscall}", list(args), dict(kwargs or {})))
        self.served.append(served)

    def number(self, small, large=(), bad=()):
        """An int or bool argument; ``bad`` ones are refused."""
        pick = self.rng.random()
        if bad and pick < 0.05:
            return self.rng.choice(bad), False
        if large and pick < 0.3:
            return self.rng.choice(large), True
        return self.rng.choice(small), True

    def population(self):
        rng = self.rng
        kind = rng.randrange(10)
        if kind <= 4:
            return list(range(rng.choice([0, 1, 2, 3, 7, 20]))), True
        if kind == 5:
            return rng.choice(["", "a", "héllo", "雪ab", "xyz" * 5]), True
        if kind == 6:
            return rng.choice([b"", b"\x00", b"\x01\x02\xff"]), True
        if kind == 7:
            return bytearray(rng.choice([b"", b"q", b"abc"])), True
        return rng.choice([{"a": 1}, None, ["a", "b"], (0, 1), 5]), False


SALTS = [
    ("abc", True),
    ("", True),
    (0, True),
    (42, True),
    (-7, True),
    (2**200, True),
    (-(2**511), True),
    (True, True),
    (False, True),
    (None, True),
    (ContractingDecimal("1.5"), True),
    ([1, "a"], True),
    ({"b": 1}, True),
    ((1, "a"), True),
]
BITS = list(range(0, 301)) + [-1, -5, True, False]
LARGE_BITS = [301, 333, 511, 512, 513, 514, 520, 600, 1024, 2**20, 2**40, 2**511]
BIG = [2**64, 2**256 + 3, 2**511, 2**512 - 1]


def _seed(calls: Calls):
    salt, served = calls.rng.choice(SALTS)
    shape = calls.rng.randrange(4)
    if shape == 0:
        calls.add("seed")
    elif shape == 1:
        calls.add("seed", [salt], served=served)
    elif shape == 2:
        calls.add("seed", kwargs={"aux_salt": salt}, served=served)
    else:
        calls.add("seed", [salt, 1], served=False)


def _getrandbits(calls: Calls):
    bits, served = calls.number(BITS, LARGE_BITS, ["8", ContractingDecimal("8")])
    if calls.rng.random() < 0.2:
        calls.add("getrandbits", kwargs={"k": bits}, served=served)
    else:
        calls.add("getrandbits", [bits], served=served)


def _randrange(calls: Calls):
    upper, served = calls.number([-3, -1, 0, 1, 2, 3, 10, 255, 256, 1000, True, False], BIG, ["x"])
    calls.add("randrange", [upper], served=served)


def _randint(calls: Calls):
    low, low_served = calls.number([-5, -1, 0, 1, 3, True, False], [-(2**511), 2**200], [None])
    high, high_served = calls.number([-5, 0, 1, 3, 6, 100, True], [2**511, 2**64], [None])
    served = low_served and high_served
    if calls.rng.random() < 0.2:
        calls.add("randint", kwargs={"b": high, "a": low}, served=served)
    else:
        calls.add("randint", [low, high], served=served)


def _choice(calls: Calls):
    items, served = calls.population()
    calls.add("choice", [items], served=served)


def _choices(calls: Calls):
    items, items_served = calls.population()
    draws, draws_served = calls.number(
        [-2, -1, 0, 1, 2, 3, 5, 30, True, False], [500, SEQUENCE_LIMIT + 1, 2**40], ["2"]
    )
    served = items_served and draws_served
    if calls.rng.random() < 0.2:
        calls.add("choices", kwargs={"items": items, "k": draws}, served=served)
    else:
        calls.add("choices", [items, draws], served=served)


def _shuffle(calls: Calls):
    items = list(range(calls.rng.choice([0, 1, 2, 5, 13, 40])))
    if calls.rng.random() < 0.05:
        calls.add("shuffle", kwargs={"items": items}, served=False)
    else:
        calls.add("shuffle", [items])


def _odd_shape(calls: Calls):
    syscall, args, kwargs = calls.rng.choice(
        [
            ("random", [1], {}),
            ("getrandbits", [], {}),
            ("getrandbits", [1, 2], {}),
            ("randint", [1], {}),
            ("randint", [1], {"a": 2}),
            ("choice", [], {"seq": [0]}),
            ("choices", [[0]], {}),
            ("randrange", [], {"stop": 3}),
        ]
    )
    calls.add(syscall, args, kwargs, served=False)


OPERATIONS = [
    (_seed, 3),
    (lambda calls: calls.add("random"), 1),
    (_getrandbits, 6),
    (_randrange, 3),
    (_randint, 3),
    (_choice, 3),
    (_choices, 3),
    (_shuffle, 3),
    (_odd_shape, 1),
]


def _context(rng: random.Random):
    context = {
        "chain_id": rng.choice(["xian-local", "", None, "c" * 40]),
        "block_num": rng.choice([0, 1, 17, 2**40, True, False, None]),
        "block_hash": rng.choice(["", "abc", None, "0"]),
        "__input_hash": rng.choice([None, "", "f00d" * 16]),
    }
    if rng.random() < 0.05:
        context[rng.choice(list(context))] = b"bytes"
        return context, False
    return context, True


def _case(seed: int):
    rng = random.Random(seed)
    context, context_served = _context(rng)
    calls = Calls(rng, refusals=int(rng.random() < 0.3))
    functions, weights = zip(*OPERATIONS, strict=True)
    if rng.random() < 0.85:
        calls.add("seed")
    for _ in range(rng.randrange(1, 40)):
        rng.choices(functions, weights)[0](calls)
    if not context_served:
        calls.served = [
            served and (call[0] != "random.seed" or vm_bound(*call) is not None)
            for call, served in zip(calls.calls, calls.served, strict=True)
        ]
    return context, calls


@pytest.mark.parametrize("block", range(8))
def test_rust_random_syscalls_reproduce_the_frozen_outcomes(block):
    served_calls = 0
    frozen = frozen_outcomes()["fuzz"]
    for seed in range(block * 100, block * 100 + 100):
        context, calls = _case(seed)
        actual = native._random_syscalls_debug(context, calls.calls)
        assert outcome_digest(actual) == frozen[str(seed)], seed
        for index, outcome in enumerate(actual):
            label = (seed, index, calls.calls[index])
            if not calls.served[index]:
                assert outcome[0] == "raised", (label, outcome)
                assert outcome[2][0] == "TypeError", (label, outcome)
                break
            served_calls += 1
        else:
            assert len(actual) == len(calls.calls)
    assert served_calls > 1000


def test_one_state_serves_the_whole_call_sequence():
    context = {"chain_id": "c", "block_num": 3, "block_hash": "h", "__input_hash": "x"}
    calls = [
        ("random.seed", ["salt"], {}),
        ("random.getrandbits", [256], {}),
        ("random.shuffle", [list(range(30))], {}),
        ("random.seed", [], {}),
        ("random.randint", [-(2**511), 2**511], {}),
    ]
    expected = native._random_syscalls_debug(context, calls)
    assert outcome_digest(expected) == frozen_outcomes()["one_state"]
    # Reseeding restarts the stream.
    again = native._random_syscalls_debug(context, calls[3:] + calls[3:])
    assert again[1] == again[3] == expected[4]
