"""In-contract dictionaries keep Python semantics under V2 equality and cost
the same per operation whatever their size.

The semantic tests run random operation sequences against a model of a
Python dictionary whose keys are compared with V2 equality (`True != 1`,
`decimal('1') == 1` inside frozensets, frozenset order does not matter).
The metering tests check that one lookup, insert, overwrite or removal does
not get more expensive as the dictionary grows.
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from contracting.local import ContractingClient

# Key source and its V2 equality class. Keys of one class are equal.
KEYS = (
    ("0", ("int", 0)),
    ("1", ("int", 1)),
    ("-1", ("int", -1)),
    ("2 ** 80", ("int", 2**80)),
    ("True", ("bool", True)),
    ("False", ("bool", False)),
    ("None", ("none",)),
    ("'a'", ("str", "a")),
    ("''", ("str", "")),
    ("'1'", ("str", "1")),
    ("b'a'", ("bytes", b"a")),
    ("(1, 2)", ("tuple", (("int", 1), ("int", 2)))),
    ("(2, 1)", ("tuple", (("int", 2), ("int", 1)))),
    ("(True,)", ("tuple", (("bool", True),))),
    ("(1,)", ("tuple", (("int", 1),))),
    ("((1,), 'a')", ("tuple", (("tuple", (("int", 1),)), ("str", "a")))),
    ("frozenset([1, 2])", ("frozenset", frozenset({("int", 1), ("int", 2)}))),
    ("frozenset([2, 1])", ("frozenset", frozenset({("int", 1), ("int", 2)}))),
    ("frozenset([decimal('1'), 2])", ("frozenset", frozenset({("int", 1), ("int", 2)}))),
    ("frozenset([True, 2])", ("frozenset", frozenset({("bool", True), ("int", 2)}))),
    ("frozenset([])", ("frozenset", frozenset())),
)

operations = st.one_of(
    st.tuples(st.just("set"), st.integers(0, len(KEYS) - 1), st.integers(0, 99)),
    st.tuples(st.just("setdefault"), st.integers(0, len(KEYS) - 1), st.integers(0, 99)),
    st.tuples(st.just("update"), st.integers(0, len(KEYS) - 1), st.integers(0, 99)),
    st.tuples(st.just("alias_set"), st.integers(0, len(KEYS) - 1), st.integers(0, 99)),
    st.tuples(st.just("copy_set"), st.integers(0, len(KEYS) - 1), st.integers(0, 99)),
    st.tuples(st.just("get"), st.integers(0, len(KEYS) - 1)),
    st.tuples(st.just("in"), st.integers(0, len(KEYS) - 1)),
    st.tuples(st.just("in_keys"), st.integers(0, len(KEYS) - 1)),
    st.tuples(st.just("pop"), st.integers(0, len(KEYS) - 1)),
    st.tuples(st.just("popitem")),
)


class Model:
    """A Python dictionary keyed by V2 equality class, keeping the first key."""

    def __init__(self):
        self.entries = {}

    def store(self, index, value):
        key = KEYS[index][1]
        first, _ = self.entries.get(key, (index, None))
        self.entries[key] = (first, value)

    @staticmethod
    def canonical(index):
        """The first key in KEYS equal to KEYS[index]."""
        return next(i for i, (_, key) in enumerate(KEYS) if key == KEYS[index][1])

    def apply(self, operation):
        kind, index = operation[0], operation[1] if len(operation) > 1 else None
        key = KEYS[index][1] if index is not None else None
        if kind in ("set", "update", "alias_set"):
            self.store(index, operation[2])
            return None
        if kind == "copy_set":
            return None
        if kind == "setdefault":
            if key not in self.entries:
                self.store(index, operation[2])
            return self.entries[key][1]
        if kind == "get":
            return self.entries.get(key, (None, None))[1]
        if kind in ("in", "in_keys"):
            return key in self.entries
        if kind == "pop":
            return self.entries.pop(key, (None, -1))[1]
        if not self.entries:
            return None
        last = next(reversed(self.entries))
        first, value = self.entries.pop(last)
        return [self.canonical(first), value]


def statement(operation):
    kind = operation[0]
    key = KEYS[operation[1]][0] if len(operation) > 1 else None
    return {
        "set": lambda: f"d[{key}] = {operation[-1]}; out.append(None)",
        "update": lambda: f"d.update({{{key}: {operation[-1]}}}); out.append(None)",
        "alias_set": lambda: f"a[{key}] = {operation[-1]}; out.append(None)",
        "copy_set": lambda: f"c = d.copy(); c[{key}] = {operation[-1]}; out.append(None)",
        "setdefault": lambda: f"out.append(d.setdefault({key}, {operation[-1]}))",
        "get": lambda: f"out.append(d.get({key}))",
        "in": lambda: f"out.append({key} in d)",
        "in_keys": lambda: f"out.append({key} in d.keys())",
        "pop": lambda: f"out.append(d.pop({key}, -1))",
        "popitem": lambda: (
            "if len(d) > 0:\n        k, v = d.popitem()\n        out.append([first(k), v])\n"
            "    else:\n        out.append(None)"
        ),
    }[kind]()


def program(sequence):
    keys = ", ".join(source for source, _ in KEYS)
    lines = [
        "def first(k):",
        f"    pool = [{keys}]",
        "    for i in range(len(pool)):",
        "        if pool[i] == k:",
        "            return i",
        "",
        "@export",
        "def run():",
        "    d = {}",
        "    a = d",
        "    out = []",
    ]
    lines += [f"    {statement(operation)}" for operation in sequence]
    lines += [
        "    return [out, [first(k) for k in d], list(d.values()), [str(k) for k in d]]",
    ]
    return "\n".join(lines)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    with ContractingClient(storage_home=tmp_path_factory.mktemp("dict-index")) as client:
        yield client


NAMES = (f"con_dict_{number}" for number in itertools.count())


def run(client, source):
    name = next(NAMES)
    client.submit(source, name=name)
    output = client.executor.execute(
        sender="stu",
        contract_name=name,
        function_name="run",
        kwargs={},
        metering=True,
        chi=1_000_000,
    )
    assert output["status_code"] == 0, output["result"]
    return output["result"]


def failing(client, source):
    name = next(NAMES)
    client.submit(source, name=name)
    return client.executor.execute(sender="stu", contract_name=name, function_name="run", kwargs={})


@pytest.fixture(scope="module")
def key_text(client):
    """The VM's text of every key in KEYS, as an entry's retained key prints."""
    keys = ", ".join(source for source, _ in KEYS)
    return run(client, f"@export\ndef run():\n    return [str(k) for k in [{keys}]]\n")


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(st.lists(operations, min_size=1, max_size=40))
def test_operation_sequences_match_a_v2_equality_model(client, key_text, sequence):
    model = Model()
    expected = [model.apply(operation) for operation in sequence]
    out, firsts, values, texts = run(client, program(sequence))
    assert out == expected
    assert firsts == [model.canonical(first) for first, _ in model.entries.values()]
    assert values == [value for _, value in model.entries.values()]
    assert texts == [key_text[first] for first, _ in model.entries.values()]


def test_iteration_order_after_removal_and_reinsertion(client):
    source = """
@export
def run():
    d = {}
    for i in range(6):
        d[i] = i
    d.pop(1)
    d.pop(4)
    d[1] = 10
    d[0] = 20
    d.setdefault(4, 40)
    return [list(d.keys()), list(d.values()), list(reversed(list(d.items())))]
"""
    keys, values, items = run(client, source)
    assert keys == [0, 2, 3, 5, 1, 4]
    assert values == [20, 2, 3, 5, 10, 40]
    assert items[0] == (4, 40) or items[0] == [4, 40]


def test_mutation_during_iteration_is_detected(client):
    grow = (
        "@export\ndef run():\n    d = {1: 1}\n    for k in d:\n        d[k + 1] = 1\n    return 1\n"
    )
    output = failing(client, grow)
    assert output["status_code"] == 1
    assert "changed size during iteration" in str(output["result"])
    overwrite = "@export\ndef run():\n    d = {1: 1, 2: 2}\n    for k in d:\n        d[k] = 0\n    return list(d.values())\n"
    assert run(client, overwrite) == [0, 0]


def test_unhashable_and_missing_keys_keep_their_errors(client):
    cases = {
        "d[[1]] = 1": "unhashable type: 'list'",
        "x = d[{}]": "unhashable type: 'dict'",
        "x = decimal('1') in d": "unhashable type: 'decimal'",
        "x = d[(1, [2])]": "unhashable type: 'list'",
        "x = d['missing']": "missing dict key missing",
        "x = d.pop('missing')": "missing dict key missing",
    }
    for operation, message in cases.items():
        source = f"@export\ndef run():\n    d = {{'a': 1}}\n    {operation}\n    return 1\n"
        output = failing(client, source)
        assert output["status_code"] == 1, operation
        assert message in str(output["result"]), (operation, output["result"])


METERING = """
def fill(size: int):
    d = {}
    for i in range(size):
        d['k' + str(i)] = i
    return d

@export
def build(size: int):
    d = fill(size)
    return len(d)

@export
def comprehension(size: int):
    d = {'k' + str(i): i for i in range(size)}
    return len(d)

@export
def probe(size: int, op: str, reps: int):
    d = fill(size)
    k = 'k' + str(size - 1)
    for i in range(reps):
        if op == 'hit':
            x = d[k]
        elif op == 'get':
            x = d.get(k)
        elif op == 'miss':
            x = 'zz' in d
        elif op == 'keys':
            x = 'zz' in d.keys()
        elif op == 'update':
            d[k] = i
        elif op == 'setdefault':
            x = d.setdefault(k, 0)
        elif op == 'pop':
            v = d.pop(k)
            d[k] = v
        elif op == 'pop_first':
            f = 'k' + str(i % size)
            v = d.pop(f)
            d[f] = v
        elif op == 'popitem':
            item = d.popitem()
            d[item[0]] = item[1]
    return 1
"""


@pytest.fixture(scope="module")
def metering_client(tmp_path_factory):
    with ContractingClient(storage_home=tmp_path_factory.mktemp("dict-metering")) as client:
        client.submit(METERING, name="con_dict_metering")
        yield client


def chi(client, function, **kwargs):
    output = client.executor.execute(
        sender="stu",
        contract_name="con_dict_metering",
        function_name=function,
        kwargs=kwargs,
        metering=True,
        chi=1_000_000,
    )
    assert output["status_code"] == 0, output["result"]
    return output["chi_used"]


def per_operation(client, size, op, reps=20):
    full = chi(client, "probe", size=size, op=op, reps=reps)
    return (full - chi(client, "probe", size=size, op=op, reps=0)) / reps


@pytest.mark.parametrize(
    "op", ["hit", "get", "miss", "keys", "update", "setdefault", "pop", "popitem"]
)
def test_one_operation_costs_the_same_at_any_size(metering_client, op):
    small = per_operation(metering_client, 10, op)
    large = per_operation(metering_client, 10_000, op)
    assert large <= small + 0.5, f"{op}: {small} chi at 10 keys, {large} chi at 10,000 keys"


def test_removal_pays_for_the_entries_it_moves(metering_client):
    """Removing the first of n entries moves the other n - 1 up."""
    last = per_operation(metering_client, 10_000, "pop")
    first = per_operation(metering_client, 10_000, "pop_first")
    moved_units = 9_999 // 16
    assert first - last >= moved_units * 24 / 1000 - 0.5, (last, first)


@pytest.mark.parametrize("function", ["build", "comprehension"])
def test_building_grows_linearly(metering_client, function):
    thousand = chi(metering_client, function, size=1_000)
    ten_thousand = chi(metering_client, function, size=10_000)
    assert ten_thousand <= 11 * thousand, (thousand, ten_thousand)
