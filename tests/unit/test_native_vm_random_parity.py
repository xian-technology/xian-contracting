"""The block host's random syscalls (Rust) against the Python random bridge.

The Rust block executor serves the contract random syscalls in vm-core
(``block_host/random.rs``); the Python path serves them with
``contracting.stdlib.bridge.random`` through ``NativeVmHost.handle_syscall``.
This fuzz sends the same calls, as the VM sends them, through both: every
call Rust serves must return the same value (after the V2 boundary) or raise
the same exception with the same text, and Rust hands a call back to the
Python path exactly when it is one of the documented cases (other argument,
salt or context types, call shapes Python refuses itself, draws above the
native bounds).
"""

from __future__ import annotations

import copy
import random

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.execution.runtime import rt
from contracting.stdlib.bridge import random as random_bridge

pytestmark = pytest.mark.optional_native

native = pytest.importorskip("xian_vm_core._native")
NativeVmHost = pytest.importorskip("xian_vm_core").NativeVmHost

MAX_NATIVE = 1 << 20
# The exception types whose category the VM keeps (python_bindings
# `builtin_exception_name`).
KEPT_TYPES = (AssertionError, TypeError, ValueError, RuntimeError, Exception, KeyError, IndexError)
HANDED_BACK = object()


def _python_exception(error):
    if type(error) in KEPT_TYPES:
        return (type(error).__name__, list(error.args))
    return None


def python_outcomes(context, calls):
    """What the VM receives from the Python path for each call."""
    previous = dict(rt.env)  # rt.env is a live proxy
    rt.env = dict(context)
    random_bridge.clear_random_state()
    outcomes = []
    try:
        for syscall_id, args, kwargs in calls:
            try:
                result = NativeVmHost.handle_syscall(
                    None, syscall_id, copy.deepcopy(args), dict(kwargs)
                )
            except Exception as error:  # noqa: BLE001 - every raise is an outcome
                outcomes.append(
                    ("raised", f"{type(error).__qualname__}: {error}", _python_exception(error))
                )
                continue
            try:
                outcomes.append(("ok", native._vm_value_debug(result)))
            except ValueError as refused:
                outcomes.append(("raised", str(refused), None))
    finally:
        random_bridge.clear_random_state()
        rt.env = previous
    return outcomes


class Calls:
    """Random syscalls as the VM issues them, each marked served or not."""

    def __init__(self, rng: random.Random, handbacks: int):
        self.rng = rng
        self.calls = []
        self.served = []
        # A hand-back ends the transaction: at most this many per sequence.
        self.handbacks = handbacks

    def add(self, syscall, args=(), kwargs=None, *, served=True):
        if not served:
            if not self.handbacks:
                return
            self.handbacks -= 1
        self.calls.append((f"random.{syscall}", list(args), dict(kwargs or {})))
        self.served.append(served)

    def number(self, small, large=(), bad=()):
        """An int or bool argument; ``bad`` ones are handed back."""
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
    (ContractingDecimal("1.5"), False),
    ([1, "a"], False),
    ({"b": 1}, False),
    ((1, "a"), False),
]
BITS = list(range(0, 301)) + [-1, -5, True, False]
LARGE_BITS = [301, 333, 511, 512, 513, 514, 520, 600, 1024, 1100, MAX_NATIVE]
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
    bits, served = calls.number(BITS, LARGE_BITS, ["8", ContractingDecimal("8"), MAX_NATIVE + 1])
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
        [-2, -1, 0, 1, 2, 3, 5, 30, True, False], [500], ["2", MAX_NATIVE + 1]
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
    calls = Calls(rng, handbacks=int(rng.random() < 0.3))
    functions, weights = zip(*OPERATIONS, strict=True)
    if rng.random() < 0.85:
        calls.add("seed")
    for _ in range(rng.randrange(1, 40)):
        rng.choices(functions, weights)[0](calls)
    if not context_served:
        calls.served = [
            served and call[0] != "random.seed" for call, served in zip(calls.calls, calls.served)
        ]
    return context, calls


@pytest.mark.parametrize("block", range(8))
def test_rust_random_syscalls_match_the_python_bridge(block):
    served_calls = 0
    for seed in range(block * 100, block * 100 + 100):
        context, calls = _case(seed)
        expected = python_outcomes(context, calls.calls)
        actual = native._random_syscalls_debug(context, calls.calls)
        for index, outcome in enumerate(actual):
            label = (seed, index, calls.calls[index])
            if outcome[0] == "handback":
                assert not calls.served[index], (label, outcome)
                assert index == len(actual) - 1
                break
            assert calls.served[index], (label, outcome)
            assert outcome == expected[index], label
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
    expected = python_outcomes(context, calls)
    assert native._random_syscalls_debug(context, calls) == expected
    # Reseeding restarts the stream.
    again = native._random_syscalls_debug(context, calls[3:] + calls[3:])
    assert again[1] == again[3] == expected[4]
