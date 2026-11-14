"""Retrieved public methods keep their receiver and bind arguments consistently."""

import pytest
from xian_compiler_core import CompilerError

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


CASES = [
    (
        "append_alias",
        "items = [1]\nf = items.append\nitems.append(2)\nf(3)\nreturn items",
        [1, 2, 3],
    ),
    (
        "rebound_name",
        "items = [1]\noriginal = items\nf = items.append\nitems = []\nf(2)\nreturn [original, items]",
        [[1, 2], []],
    ),
    (
        "callback",
        "items = []\nf = items.append\nresult = list(map(f, [2, 3]))\nreturn [items, result]",
        [[2, 3], [None, None]],
    ),
    ("sort_callback", "order = [3, 1, 2]\nreturn sorted([1, 2, 3], key=order.index)", [3, 1, 2]),
    ("split_alias", 'f = "a,b,c".split\nreturn f(sep=",", maxsplit=1)', ["a", "b,c"]),
    ("split_direct", 'return "a,b,c".split(sep=",", maxsplit=1)', ["a", "b,c"]),
    ("kwargs_hole", 'return "a b c".split(maxsplit=1)', ["a", "b c"]),
    ("sort_alias", "items = [2, 1, 3]\nf = items.sort\nf(reverse=True)\nreturn items", [3, 2, 1]),
    ("getitem_alias", 'data = {"x": 1}\nf = data.get\ndata["x"] = 3\nreturn f("x")', 3),
    ("clear_alias", "items = [1]\nf = items.clear\nf()\nreturn items", []),
    ("cycle", "items = []\nf = items.append\nf(f)\nitems.clear()\nf(4)\nreturn items", [4]),
    (
        "method_equality",
        "items = []\nf = items.append\nreturn [f is f, f == items.append, f == [].append]",
        [True, True, False],
    ),
    ("exception_args", 'value = Exception("x", 3)\nreturn list(value.args)', ["x", 3]),
    ("storage_alias", "put = state.set\nget = state.get\nput(7)\nreturn get()", 7),
    (
        "method_keys",
        "items = []\nf = items.append\ndata = {f: 7}\nreturn [data[f], data[items.append]]",
        [7, 7],
    ),
    ("unbound_str", 'f = str.upper\nreturn f("ab")', "AB"),
    ("unbound_list", "items = [1]\nf = list.append\nf(items, 2)\nreturn items", [1, 2]),
    ("helper_return", "items = []\nf = append_for(items)\nf(5)\nreturn items", [5]),
    (
        "datetime_keywords",
        'f = datetime.datetime.strptime\nreturn str(f(format="%Y", date_string="2026"))',
        "2026-01-01 00:00:00",
    ),
]
INVALID = [
    ("return_class_method", "return datetime.datetime.strptime"),
    ("nested_return_class_method", "return [datetime.datetime.strptime]"),
    ("store_class_method", "state.set(datetime.datetime.strptime)\nreturn 1"),
    (
        "class_method_is_not_class",
        "return issubclass(datetime.datetime.strptime, datetime.datetime)",
    ),
    ("unbound_wrong_receiver", "f = str.upper\nreturn f(1)"),
    ("unbound_missing_receiver", "return list.append()"),
    ("unknown_attribute", "return [].not_a_method(1)"),
    ("private_attribute", "return [].__class__"),
    ("positional_only", "return [].append(value=1)"),
    ("duplicate_binding", 'return "a,b".split(",", sep=",")'),
    ("unknown_keyword", 'return "a,b".split(unknown=1)'),
    ("aliased_invalid_keyword", "f = [].append\nreturn f(value=1)"),
    ("return_method", "return [].append"),
    ("nested_return_method", 'return {"f": [].append}'),
    ("store_method", "state.set([].append)\nreturn 1"),
    ("store_nested_method", 'state.set({"f": [].append})\nreturn 1'),
]


def execute_source(home, body):
    source = (
        "state = Variable()\ndef append_for(values):\n    return values.append\n@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    with Driver(storage_home=home, vm_profile="xian_vm_v2") as driver:
        driver.set_contract_from_source("con_bound", source, owner=None)
        driver.commit()
        from tests.vm_calls import execute_contract

        result = execute_contract(
            driver=driver,
            contract_name="con_bound",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_bound"},
            meter=False,
        )
        return result.status_code, result.result, result.writes


@pytest.mark.parametrize(("case_id", "body", "expected"), CASES, ids=[case[0] for case in CASES])
def test_bound_method_semantics(tmp_path, case_id, body, expected):
    status, result, _ = execute_source(tmp_path, body)
    assert status == 0, result
    assert result == expected


@pytest.mark.parametrize(("case_id", "body"), INVALID, ids=[case[0] for case in INVALID])
def test_bound_method_invalid_calls_and_boundaries(tmp_path, case_id, body):
    if case_id == "private_attribute":
        with pytest.raises(CompilerError, match="E002"):
            execute_source(tmp_path, body)
        return
    status, result, writes = execute_source(tmp_path, body)
    assert status == 1, result
    assert writes == {}


CROSS_PAYLOADS = [
    "notice",
    "state",
    "[state]",
    "append_for",
    "map(append_for, [])",
    "state.get",
    "[state.get]",
    '{"f": state.get}',
    "map(state.get, [])",
    'Exception({"f": state.get})',
    "data.keys().mapping",
    "[data.keys().mapping]",
]


def execute_cross_contract(home, caller_body, callee_source):
    from tests.vm_calls import execute_contract

    caller = (
        'import con_bound_target\nstate = Variable()\nnotice = LogEvent(event="Boundary", params={"value": int})\ndef append_for(values):\n    return values.append\n@export\ndef probe():\n'
        + "".join("    " + line + "\n" for line in caller_body.splitlines())
    )
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_bound_target", callee_source, owner=None)
        driver.set_contract_from_source("con_bound_caller", caller, owner=None)
        driver.commit()
        result = execute_contract(
            driver=driver,
            contract_name="con_bound_caller",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_bound_caller"},
            meter=False,
        )
        return result.status_code, result.result, result.writes, result.events


@pytest.mark.parametrize("payload", CROSS_PAYLOADS)
def test_execution_local_values_cannot_cross_nested_contract_inputs(tmp_path, payload):
    source = (
        "state = Variable()\n@export\ndef consume(value: Any):\n    state.set(2)\n    return 7\n"
    )
    body = f'state.set(1)\ndata = {{"x": 3}}\nreturn con_bound_target.consume({payload})'
    status, result, writes, events = execute_cross_contract(tmp_path, body, source)
    assert status == 1 and "cannot cross contract boundaries" in str(result)
    assert writes == {} and events == []


@pytest.mark.parametrize("payload", ["[].append", "[{}.get]", "{}.keys().mapping"])
def test_execution_local_values_cannot_cross_nested_contract_results(tmp_path, payload):
    source = f"state = Variable()\n@export\ndef create():\n    state.set(2)\n    return {payload}\n"
    status, result, writes, events = execute_cross_contract(
        tmp_path, "state.set(1)\nreturn con_bound_target.create()", source
    )
    assert status == 1 and "cannot cross contract boundaries" in str(result)
    assert writes == {} and events == []


def test_bound_storage_callback_cannot_resolve_other_contract_state(tmp_path):
    source = "state = Variable()\n@export\ndef consume(callback: Any):\n    state.set(2)\n    return callback()\n"
    status, result, writes, _ = execute_cross_contract(
        tmp_path, "state.set(1)\nreturn con_bound_target.consume(state.get)", source
    )
    assert status == 1 and "bound methods cannot cross contract boundaries" in str(result)
    assert writes == {}


def test_plain_shared_values_and_cycles_keep_identity_across_contract_calls(tmp_path):
    source = (
        "@export\ndef mutate(values: list):\n"
        "    assert values[0] is values\n"
        "    values.clear()\n"
        "    values.append(2)\n"
    )
    body = "items = []\nitems.append(items)\ncon_bound_target.mutate(items)\nreturn items"
    status, result, _, _ = execute_cross_contract(tmp_path, body, source)
    assert status == 0 and result == [2]


def test_global_storage_reference_cannot_resolve_other_contract_state(tmp_path):
    source = "state = Variable()\n@export\ndef consume(resource: Any):\n    state.set(2)\n    return resource.get()\n"
    status, result, writes, _ = execute_cross_contract(
        tmp_path, "state.set(1)\nreturn con_bound_target.consume(state)", source
    )
    assert status == 1 and "global storage references cannot cross contract boundaries" in str(
        result
    )
    assert writes == {}


def test_local_function_reference_cannot_call_same_named_callee_function(tmp_path):
    source = "def append_for(values):\n    return 99\n@export\ndef consume(callback: Any):\n    return callback([])\n"
    status, result, writes, _ = execute_cross_contract(
        tmp_path, "state.set(1)\nreturn con_bound_target.consume(append_for)", source
    )
    assert status == 1 and "local functions cannot cross contract boundaries" in str(result)
    assert writes == {}


def test_explicit_foreign_storage_reference_keeps_target_across_contract_calls(tmp_path):
    source = "state = Variable()\n@export\ndef consume(resource: Any):\n    state.set(2)\n    return resource.get()\n"
    body = 'state.set(1)\nresource = ForeignVariable(foreign_contract="con_bound_caller", foreign_name="state")\nreturn con_bound_target.consume(resource)'
    status, result, _, _ = execute_cross_contract(tmp_path, body, source)
    assert status == 0 and result == 1


@pytest.mark.parametrize("payload", ["state.get", "state", "append_for", "{}.keys().mapping"])
def test_callee_cannot_inject_capabilities_through_shared_input_mutation(tmp_path, payload):
    source = (
        "state = Variable()\ndef append_for(values):\n    return values.append\n"
        "@export\ndef inject(values: list):\n    state.set(2)\n"
        f"    values.append({payload})\n"
    )
    body = "state.set(1)\nitems = []\ncon_bound_target.inject(items)\nreturn 7"
    status, result, writes, events = execute_cross_contract(tmp_path, body, source)
    assert status == 1 and "cannot cross contract boundaries" in str(result)
    assert writes == {} and events == []
