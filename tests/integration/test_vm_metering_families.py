"""Operations whose work grows with their input are charged by that input.

Each probe runs one operation `reps` times on an input of `size`. The chi of
one operation is the difference to a run with zero repetitions, so building
the input does not count. Every family below used to cost a constant few chi
whatever the input size; `xvm-gas-5` charges per scanned byte, compared byte,
visited element, traversed boundary node or scanned storage entry.
"""

import pytest

from contracting.local import ContractingClient

SIZE = 65_536
TEXT = f"s = 'a' * {SIZE}; t = 'a' * {SIZE - 1} + 'b'; u = 'a' * {SIZE}"
HELPER = """
@export
def ping(x: Any):
    return 1
"""

# name -> (setup, operation)
PROBES = {
    "lower": (TEXT, "x = s.lower()"),
    "upper": (TEXT, "x = s.upper()"),
    "isalpha": (TEXT, "x = s.isalpha()"),
    "isdigit": (TEXT, "x = s.isdigit()"),
    "islower": (TEXT, "x = s.islower()"),
    "isalnum": (TEXT, "x = s.isalnum()"),
    "split_whitespace": (TEXT, "x = s.split()"),
    "find": (TEXT, "x = s.find('b')"),
    "count": (TEXT, "x = s.count('b')"),
    "startswith": (TEXT, "x = s.startswith(t)"),
    "endswith": (TEXT, "x = s.endswith(t)"),
    "replace": (TEXT, "x = s.replace('b', 'c')"),
    "split_separator": (TEXT, "x = s.split('b')"),
    "join": (f"l = ['a'] * {SIZE // 2}", "x = ''.join(l)"),
    "contains": (TEXT, "x = 'b' in s"),
    "slice": (TEXT, "x = s[1:]"),
    "slice_step": (TEXT, "x = s[::-1]"),
    "index_character": (TEXT, f"x = s[{SIZE - 1}]"),
    "decimal_text": (f"d = '0' * {SIZE} + '1'", "x = decimal(d)"),
    "equal": (TEXT, "x = s == u"),
    "less": (TEXT, "x = s < t"),
    "list_contains": (TEXT + "; l = [t, t, t, t]", "x = u in l"),
    "list_equal_copy": ("l = list(range(20000)); m = list(l)", "x = l == m"),
    "bytes_contains": (TEXT + "; b = s.encode(); k = t.encode()", "x = k in b"),
    "boundary_list": ("h = importlib.import_module('con_helper'); l = list(range(20000))", "h.ping(l)"),
    "hash_all": ("", "x = seeded.all()"),
    "hash_all_written": ("for j in range(300):; seeded['w' + str(j)] = j", "x = seeded.all()"),
    "int_text": ("d = '0' * 8000 + '1'", "x = int(d)"),
}

SEEDED = 500

# Minimum chi for one operation, from the element work it must pay for. One
# unit is 24 raw chi (1,000 raw chi = 1 chi).
UNIT = 24
CHARACTERS = SIZE // 2 * UNIT // 1000  # one unit per 2 bytes of per-character work
SEARCHED = SIZE // 8 * UNIT // 1000  # one unit per 8 bytes searched or copied
COMPARED = SIZE // 128 * UNIT // 1000  # one unit per 128 bytes compared
MINIMUM = {
    **dict.fromkeys(
        ["lower", "upper", "isalpha", "isdigit", "islower", "isalnum", "split_whitespace"],
        CHARACTERS,
    ),
    **dict.fromkeys(
        [
            "find",
            "count",
            "startswith",
            "endswith",
            "replace",
            "split_separator",
            "join",
            "contains",
            "slice",
            "slice_step",
            "index_character",
            "decimal_text",
            "bytes_contains",
        ],
        SEARCHED,
    ),
    "equal": COMPARED,
    "less": COMPARED,
    "list_contains": 4 * COMPARED,
    "list_equal_copy": 20_000 * UNIT // 1000,
    "boundary_list": 20_000 * UNIT // 1000,
    "hash_all": SEEDED * 2560 // 1000,  # fixed cost per scanned entry
    "hash_all_written": (SEEDED + 300) * 2560 // 1000,
    "int_text": 8001 // 2 * UNIT // 1000,
}


def statements(text):
    """Split `a; b`; a line ending in `:` indents the lines after it."""
    lines, indent = [], ""
    for line in filter(None, text.split("; ")):
        lines.append(indent + line)
        indent += "    " if line.endswith(":") else ""
    return lines


def probe_source():
    lines = [
        "seeded = Hash(default_value=0)",
        "@export",
        "def seed(count: int):",
        "    for j in range(count):",
        "        seeded['k' + str(j)] = j",
    ]
    for name, (setup, operation) in PROBES.items():
        lines += ["@export", f"def {name}(reps: int):"]
        lines += [f"    {line}" for line in statements(setup)]
        lines += ["    for rep in range(reps):", f"        {operation}", "    return 1"]
    return "\n".join(lines)


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    with ContractingClient(storage_home=tmp_path_factory.mktemp("families")) as client:
        client.submit(HELPER, name="con_helper")
        client.submit(probe_source(), name="con_families")
        client.executor.execute(
            sender="stu",
            contract_name="con_families",
            function_name="seed",
            kwargs={"count": SEEDED},
            auto_commit=True,
        )
        yield client


def chi(client, name, reps):
    output = client.executor.execute(
        sender="stu",
        contract_name="con_families",
        function_name=name,
        kwargs={"reps": reps},
        metering=True,
        chi=1_000_000,
    )
    assert output["status_code"] == 0, output["result"]
    return output["chi_used"]


@pytest.mark.parametrize("name", PROBES)
def test_operation_cost_grows_with_its_input(client, name):
    per_operation = (chi(client, name, 2) - chi(client, name, 0)) / 2
    assert per_operation >= MINIMUM[name], f"{name}: {per_operation} chi"
