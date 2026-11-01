"""Public event/ORM methods preserve their declaring storage authority."""

import pytest

from tests.compatibility.runner import encode, run_case

TARGET = """
balance = Variable(default_value=7)
ledger = Hash(default_value=0)
@export
def seed():
    balance.set(7)
    ledger['alice'] = 8
@export
def read():
    return [balance.get(), ledger['alice']]
"""
DECLARATIONS = """
import con_event_orm_target
balance = Variable(default_value=0)
items = Variable(default_value=[1])
ledger = Hash(default_value=0)
foreign_balance = ForeignVariable(foreign_contract='con_event_orm_target', foreign_name='balance')
foreign_ledger = ForeignHash(foreign_contract='con_event_orm_target', foreign_name='ledger')
Changed = LogEvent(event='Changed', params={'value': indexed(int)})
"""
ENGINES = [False, pytest.param(True, marks=pytest.mark.optional_native)]


def execute(tmp_path, native, body):
    return run_case(
        {
            "id": "event_orm_methods",
            "dependencies": {"con_event_orm_target": TARGET},
            "source": DECLARATIONS
            + "\n@export\ndef probe():\n"
            + "".join("    " + line + "\n" for line in body.splitlines()),
        },
        tmp_path,
        native=native,
    )


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "body",
    [
        "Changed.write_event({'value': 3})",
        "Changed.write_event(event_data={'value': 3})",
        "emit = Changed.write_event\nemit({'value': 3})",
        "emit = Changed\nemit({'value': 3})",
        "emit = Changed\nemit(data={'value': 3})",
        "Changed(data={'value': 3})",
        "cls = importlib.Var('e', LogEvent).type\ncls.write_event(Changed, {'value': 3})",
        "cls = importlib.Var('e', LogEvent).type\nf = cls.write_event\nf(self=Changed, event_data={'value': 3})",
    ],
)
def test_event_public_call_shapes(tmp_path, native, body):
    actual = execute(tmp_path, native, body + "\nreturn True")
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(True)
    assert actual["events"] == encode(
        [
            {
                "contract": "baseline_event_orm_methods",
                "event": "Changed",
                "signer": "alice",
                "caller": "alice",
                "data_indexed": {"value": 3},
                "data": {},
            }
        ]
    )


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "call",
    [
        "Changed({'value': 3}, {'value': 4})",
        "Changed(value=3)",
        "Changed({'value': 3}, data={'value': 4})",
        "Changed()",
        "Changed.write_event({'value': 3}, event_data={'value': 4})",
        "Changed.write_event(data={'value': 3})",
        "Changed.write_event({'wrong': 3})",
        "Changed.write_event({'value': 'wrong'})",
        "Changed.write_event({'value': 3, 'extra': 4})",
    ],
)
def test_event_arguments_validate_before_emitting(tmp_path, native, call):
    actual = execute(tmp_path, native, call + "\nreturn True")
    assert actual["status_code"] == 1, actual
    assert actual["events"] == encode([])
    assert actual["writes"] == encode({})


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("cls = importlib.Var('v', Variable).type\nreturn cls.get(balance)", 0),
        ("cls = importlib.Var('v', Variable).type\ncls.set(balance, 3)\nreturn balance.get()", 3),
        (
            "cls = importlib.Var('v', Variable).type\ncls.set(self=balance, value=3)\nreturn balance.get()",
            3,
        ),
        (
            "cls = importlib.Var('v', Variable).type\nf = cls.append\nf(items, 3)\nreturn items.get()",
            [1, 3],
        ),
        ("cls = importlib.Var('v', ForeignVariable).type\nreturn cls.get(balance)", 0),
        ("cls = importlib.Var('v', Variable).type\nreturn cls.get(foreign_balance)", None),
        ("ledger['alice'] = 3\ncls = importlib.Var('v', Hash).type\nreturn cls.all(ledger)", [3]),
        (
            "ledger['alice'] = 3\ncls = importlib.Var('v', Hash).type\ncls.clear(ledger)\nreturn ledger['alice']",
            0,
        ),
        (
            "con_event_orm_target.seed()\ncls = importlib.Var('v', Hash).type\ncls.clone_from(ledger, foreign_ledger)\nreturn ledger['alice']",
            8,
        ),
    ],
)
def test_unbound_orm_calls_use_existing_storage_paths(tmp_path, native, body, expected):
    actual = execute(tmp_path, native, body)
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(expected)


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "body",
    [
        "cls = importlib.Var('v', Variable).type\ncls.set(foreign_balance, 99)",
        "cls = importlib.Var('v', Hash).type\ncls.clear(foreign_ledger)",
        "cls = importlib.Var('v', Hash).type\ncls.clone_from(foreign_ledger, ledger)",
        "cls = importlib.Var('v', ForeignVariable).type\ncls.set(balance, 99)",
        "cls = importlib.Var('v', ForeignHash).type\ncls.clear(ledger)",
        "cls = importlib.Var('v', Variable).type\ncls.get(ledger)",
        "cls = importlib.Var('v', Variable).type\ncls.set(ledger, 99)",
        "cls = importlib.Var('v', Hash).type\ncls.all(balance)",
        "cls = importlib.Var('v', LogEvent).type\ncls.write_event(balance, {'value': 1})",
    ],
)
def test_unbound_orm_never_grants_wrong_receiver_authority(tmp_path, native, body):
    actual = execute(tmp_path, native, "con_event_orm_target.seed()\n" + body + "\nreturn True")
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({})
    assert actual["events"] == encode([])


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    ("schema", "value", "succeeds"),
    [
        ("str", "'é' * 512", True),
        ("str", "'é' * 513", False),
        ("str", "'x' * 1024", True),
        ("str", "'x' * 1025", False),
        ("int", "'bad'", False),
        ("int", "True", True),
        ("bool", "1", False),
        ("(str, int)", "3", True),
        ("bytes", "b'a'", True),
        ("bytearray", "bytearray(b'a')", True),
        ("set", "set([1, 2])", True),
        ("frozenset", "frozenset([1, 2])", True),
    ],
)
def test_event_value_type_and_utf8_limit(tmp_path, native, schema, value, succeeds):
    actual = run_case(
        {
            "id": "event_validation",
            "source": f"Event = LogEvent(event='Validated', params={{'value': {schema}}})\n"
            f"@export\ndef probe():\n    Event({{'value': {value}}})\n    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == (0 if succeeds else 1), actual
    if not succeeds:
        assert actual["events"] == encode([])


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    "params",
    [
        "{}",
        "{'value': list}",
        "{'value': ()}",
        "{'value': (int, 7)}",
        "{'value': {'type': int, 'idx': 1}}",
        "{'value': {'type': int, 'extra': 1}}",
        "{'a': indexed(int), 'b': indexed(int), 'c': indexed(int), 'd': indexed(int)}",
        "{'': int}",
        "{1: int}",
    ],
)
def test_event_schema_validation(tmp_path, native, params):
    actual = run_case(
        {
            "id": "event_schema",
            "source": f"Event = LogEvent(event='Validated', params={params})\n"
            "@export\ndef probe():\n    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual.get("status_code") == 1 or actual["admission"] == "rejected", actual


@pytest.mark.parametrize("native", ENGINES)
def test_emitted_mutable_value_is_a_snapshot(tmp_path, native):
    actual = run_case(
        {
            "id": "event_snapshot",
            "source": "Event = LogEvent(event='Snapshot', params={'value': bytearray})\n"
            "@export\ndef probe():\n    value = bytearray(b'a')\n"
            "    Event({'value': value})\n    value[0] = 98\n    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == 0, actual
    assert actual["events"] == encode(
        [
            {
                "contract": "baseline_event_snapshot",
                "event": "Snapshot",
                "signer": "alice",
                "caller": "alice",
                "data_indexed": {},
                "data": {"value": bytearray(b"a")},
            }
        ]
    )


@pytest.mark.parametrize("native", ENGINES)
def test_storage_handle_transfer_cannot_delegate_writes(tmp_path, native):
    actual = run_case(
        {
            "id": "orm_transfer",
            "dependencies": {
                "con_orm_receiver": "@export\ndef mutate(storage: Any):\n    storage['key'] = 99\n"
            },
            "source": "import con_orm_receiver\nledger = Hash(default_value=0)\n"
            "Changed = LogEvent(event='Changed', params={'value': int})\n"
            "@export\ndef probe():\n    ledger['pending'] = 1\n"
            "    Changed({'value': 1})\n    con_orm_receiver.mutate(ledger)\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({})
    assert actual["events"] == encode([])


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    ("declarations", "mutation", "indexed"),
    [
        (
            "SCHEMA = {'value': int}\nEvent = LogEvent(event='Snapshot', params=SCHEMA)\n",
            "SCHEMA['value'] = str",
            False,
        ),
        (
            "SPEC = indexed(int)\nEvent = LogEvent(event='Snapshot', params={'value': SPEC})\n",
            "SPEC['idx'] = False",
            True,
        ),
    ],
)
def test_event_schema_is_fixed_at_declaration(tmp_path, native, declarations, mutation, indexed):
    actual = run_case(
        {
            "id": "event_schema_snapshot",
            "source": declarations
            + "@export\ndef probe():\n    "
            + mutation
            + "\n    Event({'value': 7})\n    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == 0, actual
    assert actual["events"] == encode(
        [
            {
                "contract": "baseline_event_schema_snapshot",
                "event": "Snapshot",
                "signer": "alice",
                "caller": "alice",
                "data_indexed": {"value": 7} if indexed else {},
                "data": {} if indexed else {"value": 7},
            }
        ]
    )


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("return indexed(int)['type'] is int", True),
        ("return indexed((int,))['type'] is int", True),
        ("return len(indexed(())['type'])", 0),
        ("return len(indexed((int, str))['type'])", 2),
        ("value = []\nreturn indexed(value)['type'] is value", True),
    ],
)
def test_indexed_normalizes_one_tuple_without_replacing_members(tmp_path, native, body, expected):
    actual = run_case(
        {
            "id": "indexed_values",
            "source": "@export\ndef probe():\n"
            + "".join("    " + line + "\n" for line in body.splitlines()),
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(expected)


@pytest.mark.parametrize("native", ENGINES)
def test_indexed_requires_at_least_one_positional_argument(tmp_path, native):
    actual = run_case(
        {
            "id": "indexed_empty",
            "source": "@export\ndef probe():\n    indexed()\n    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["status_code"] == 1, actual
    assert actual["events"] == encode([])


@pytest.mark.optional_native
def test_indexed_tuple_work_is_metered_and_failure_rolls_back(tmp_path):
    import xian_vm_core

    from contracting.storage.driver import Driver

    source = """
state = Variable(default_value=0)
Changed = LogEvent(event='Changed', params={'value': int})
@export
def probe(count: int):
    state.set(1)
    Changed({'value': 1})
    types = (int,) * 4096
    for i in range(count):
        indexed(types)
    return True
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_indexed_budget", source, owner=None)
        driver.commit()

        def run(count, budget=100_000_000):
            return xian_vm_core.execute_contract(
                driver=driver,
                contract_name="con_indexed_budget",
                function_name="probe",
                kwargs={"count": count},
                context={
                    "signer": "alice",
                    "caller": "alice",
                    "this": "con_indexed_budget",
                    "owner": None,
                },
                meter=True,
                chi_budget_raw=budget,
            )

        once, twice = run(1), run(2)
        assert once.status_code == twice.status_code == 0, (once.result, twice.result)
        extra_work = twice.raw_cost - once.raw_cost
        assert extra_work >= 4096 * 32
        failed = run(2, once.raw_cost + extra_work // 2)
        assert failed.status_code == 1
        assert "Out of chi" in str(failed.result)
        assert failed.writes == {}
        assert failed.events == []
        assert run(1).status_code == 0
