"""Authored lexical-scope outcomes, checked against the pinned historical runtime."""

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


def contract(body, prelude="value = 41", parameters=""):
    return (
        prelude
        + "\n@export\ndef probe("
        + parameters
        + "):\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )


# Error cases must be admitted and execute; a compile/setup failure is never a pass.
CASES = [
    ("read_before_assignment", contract("result = value\nvalue = 7\nreturn result"), None, True),
    ("self_assignment", contract("value = value + 1\nreturn value"), None, True),
    ("unreachable_assignment", contract("return value\nvalue = 7"), None, True),
    ("untaken_branch", contract("if False:\n    value = 7\nreturn value"), None, True),
    ("taken_branch", contract("if True:\n    value = 7\nreturn value"), 7, False),
    ("empty_for_target", contract("for value in []:\n    pass\nreturn value"), None, True),
    (
        "for_iterable_before_target",
        contract("for value in [value]:\n    pass\nreturn value"),
        None,
        True,
    ),
    ("nonempty_for_target", contract("for value in [3, 7]:\n    pass\nreturn value"), 7, False),
    ("untaken_while_body", contract("while False:\n    value = 7\nreturn value"), None, True),
    ("augmented_assignment", contract("value += 1\nreturn value"), None, True),
    (
        "destructuring_target",
        contract("result = value\nvalue, other = [7, 9]\nreturn result"),
        None,
        True,
    ),
    (
        "starred_target",
        contract("result = value\nother, *value = [7, 9]\nreturn result"),
        None,
        True,
    ),
    (
        "branch_nested_target",
        contract("if False:\n    for other in []:\n        value = 7\nreturn value"),
        None,
        True,
    ),
    ("parameter_read", contract("return value", parameters="value: int = 7"), 7, False),
    (
        "parameter_augassign",
        contract("value += 2\nreturn value", parameters="value: int = 7"),
        9,
        False,
    ),
    (
        "parameter_branch",
        contract("if False:\n    value = 9\nreturn value", parameters="value: int = 7"),
        7,
        False,
    ),
    ("module_read", contract("return value"), 41, False),
    (
        "module_subscript_mutation",
        contract("value[0] += 1\nreturn value", "value = [41]"),
        [42],
        False,
    ),
    (
        "builtin_before_assignment",
        contract("result = len([1, 2])\nlen = 7\nreturn result", ""),
        None,
        True,
    ),
    ("builtin_parameter", contract("return len", "", "len: int = 7"), 7, False),
    ("builtin_assigned_noncallable", contract("len = 7\nreturn len([1])", ""), None, True),
    (
        "function_before_assignment",
        contract("result = helper()\nhelper = 7\nreturn result", "def helper():\n    return 41"),
        None,
        True,
    ),
    (
        "function_assigned_noncallable",
        contract("helper = 7\nreturn helper()", "def helper():\n    return 41"),
        None,
        True,
    ),
    (
        "module_alias_before_assignment",
        contract("result = datetime.datetime(2026, 1, 1)\ndatetime = 7\nreturn result", ""),
        None,
        True,
    ),
    (
        "storage_before_assignment",
        contract("result = state.get()\nstate = 7\nreturn result", "state = Variable()"),
        None,
        True,
    ),
    (
        "storage_assigned_dict",
        contract("state = {'x': 7}\nreturn state.get('x')", "state = Variable()"),
        7,
        False,
    ),
    (
        "hash_assigned_dict",
        contract(
            "state = {'x': 7}\nstate['x'] += 2\nreturn state['x']", "state = Hash(default_value=0)"
        ),
        9,
        False,
    ),
    (
        "comprehension_preserves_module",
        contract("result = [value for value in [1, 2]]\nreturn [value, result]"),
        [41, [1, 2]],
        False,
    ),
    (
        "comprehension_preserves_local",
        contract("value = 9\nresult = [value for value in [1, 2]]\nreturn [value, result]"),
        [9, [1, 2]],
        False,
    ),
    (
        "comprehension_outermost_iterable",
        contract("value = [1, 2]\nreturn [value for value in value]"),
        [1, 2],
        False,
    ),
    (
        "comprehension_global_outermost_iterable",
        contract("return [value for value in value]", "value = [1, 2]"),
        [1, 2],
        False,
    ),
    (
        "comprehension_unbound_outermost_iterable",
        contract("result = [item for item in value]\nvalue = [1]\nreturn result", "value = [1, 2]"),
        None,
        True,
    ),
    (
        "comprehension_later_target_in_iterable",
        contract("return [item for item in [1] for value in value]", "value = [2]"),
        None,
        True,
    ),
    (
        "comprehension_later_target_in_filter",
        contract("return [item for item in [1] if value for value in [2]]"),
        None,
        True,
    ),
    (
        "comprehension_previous_target",
        contract("return [item for group in [[1, 2], [3]] for item in group]"),
        [1, 2, 3],
        False,
    ),
    (
        "nested_comprehension",
        contract("return [[value for value in row] for row in [[1, 2], [3]]]"),
        [[1, 2], [3]],
        False,
    ),
    (
        "dict_comprehension_target",
        contract("result = {str(value): value + 1 for value in [1, 2]}\nreturn [value, result]"),
        [41, {"1": 2, "2": 3}],
        False,
    ),
    ("comprehension_builtin_target", contract("return [len for len in [1, 2]]", ""), [1, 2], False),
    (
        "comprehension_storage_target",
        contract("return [state.get('x') for state in [{'x': 7}]]", "state = Variable()"),
        [7],
        False,
    ),
    (
        "comprehension_hash_target",
        contract("return [state['x'] for state in [{'x': 7}]]", "state = Hash(default_value=0)"),
        [7],
        False,
    ),
    (
        "builtin_assigned_callable",
        contract("len = helper\nreturn len([1, 2])", "def helper(values):\n    return 7"),
        7,
        False,
    ),
    (
        "function_assigned_callable",
        contract(
            "helper = replacement\nreturn helper()",
            "def helper():\n    return 41\ndef replacement():\n    return 7",
        ),
        7,
        False,
    ),
    (
        "module_assigned_dict",
        contract("datetime = {'x': 7}\nreturn datetime.get('x')", ""),
        7,
        False,
    ),
    (
        "comprehension_builtin_callable",
        contract("return [len([1, 2]) for len in [helper]]", "def helper(values):\n    return 7"),
        [7],
        False,
    ),
    (
        "comprehension_function_callable",
        contract(
            "return [helper() for helper in [replacement]]",
            "def helper():\n    return 41\ndef replacement():\n    return 7",
        ),
        [7],
        False,
    ),
    (
        "comprehension_module_target",
        contract("return [datetime.get('x') for datetime in [{'x': 7}]]", ""),
        [7],
        False,
    ),
    (
        "nested_comprehension_outermost_iterable",
        contract("return [[value for value in value] for value in [[1, 2], [3]]]"),
        [[1, 2], [3]],
        False,
    ),
    (
        "comprehension_destructured_target",
        contract(
            "result = [value + other for value, other in [(1, 2), (3, 4)]]\nreturn [value, result]"
        ),
        [41, [3, 7]],
        False,
    ),
    (
        "comprehension_outermost_evaluated_once",
        contract(
            "result = [item for item in source()]\nreturn [result, calls]",
            "calls = []\ndef source():\n    calls.append(1)\n    return [2]",
        ),
        [[2], [1]],
        False,
    ),
    (
        "function_scope_isolation",
        contract("value = 7\nreturn helper()", "value = 41\ndef helper():\n    return value"),
        41,
        False,
    ),
]


ARGUMENT_FAILURE = "def fail():\n    raise Exception('argument evaluated first')"
CASES += [
    (
        "unbound_builtin_precedes_argument",
        contract("result = len(fail())\nlen = 7\nreturn result", ARGUMENT_FAILURE),
        None,
        True,
    ),
    (
        "unbound_function_precedes_argument",
        contract(
            "result = helper(fail())\nhelper = 7\nreturn result",
            ARGUMENT_FAILURE + "\ndef helper(value):\n    return value",
        ),
        None,
        True,
    ),
    (
        "unbound_module_precedes_argument",
        contract(
            "result = datetime.datetime(fail())\ndatetime = 7\nreturn result", ARGUMENT_FAILURE
        ),
        None,
        True,
    ),
    (
        "unbound_storage_precedes_argument",
        contract(
            "result = state.set(fail())\nstate = 7\nreturn result",
            "state = Variable()\n" + ARGUMENT_FAILURE,
        ),
        None,
        True,
    ),
    (
        "noncallable_evaluates_argument",
        contract("len = 7\nreturn len(fail())", ARGUMENT_FAILURE),
        None,
        True,
    ),
    (
        "callback_local_before_assignment",
        contract(
            "value = 7\nreturn list(map(callback, [1]))",
            "value = 41\ndef callback(item):\n    result = value\n    value = item\n    return result",
        ),
        None,
        True,
    ),
    (
        "callback_uses_module_scope",
        contract(
            "value = 7\nreturn list(map(callback, [1, 2]))",
            "value = 41\ndef callback(item):\n    return value + item",
        ),
        [42, 43],
        False,
    ),
    (
        "callback_locals_preserve_caller",
        contract(
            "value = 7\nresult = list(map(callback, [1, 2]))\nreturn [value, result]",
            "value = 41\ndef callback(item):\n    value = item\n    return value",
        ),
        [7, [1, 2]],
        False,
    ),
]

# The native VM exposes execution errors as RuntimeError, so compare the
# specific semantic category/name without requiring a public exception class.
UNBOUND_NAMES = {
    "read_before_assignment": "value",
    "self_assignment": "value",
    "unreachable_assignment": "value",
    "untaken_branch": "value",
    "empty_for_target": "value",
    "for_iterable_before_target": "value",
    "untaken_while_body": "value",
    "augmented_assignment": "value",
    "destructuring_target": "value",
    "starred_target": "value",
    "branch_nested_target": "value",
    "builtin_before_assignment": "len",
    "function_before_assignment": "helper",
    "module_alias_before_assignment": "datetime",
    "storage_before_assignment": "state",
    "comprehension_unbound_outermost_iterable": "value",
    "comprehension_later_target_in_iterable": "value",
    "comprehension_later_target_in_filter": "value",
    "unbound_builtin_precedes_argument": "len",
    "unbound_function_precedes_argument": "helper",
    "unbound_module_precedes_argument": "datetime",
    "unbound_storage_precedes_argument": "state",
    "callback_local_before_assignment": "value",
}
NONCALLABLE_CASES = {"builtin_assigned_noncallable", "function_assigned_noncallable"}


def assert_failure_category(case_id, result):
    diagnostic = str(result).replace("__", "")
    if case_id in UNBOUND_NAMES:
        name = UNBOUND_NAMES[case_id]
        assert f"cannot access local variable '{name}'" in diagnostic, diagnostic
        assert "not associated with a value" in diagnostic, diagnostic
    elif case_id in NONCALLABLE_CASES:
        assert "not callable" in diagnostic, diagnostic
        assert "int" in diagnostic, diagnostic
    else:
        assert case_id == "noncallable_evaluates_argument", case_id
        assert diagnostic == "argument evaluated first", diagnostic


def execute_source(home, source):
    with Driver(storage_home=home, vm_profile="xian_vm_v2") as driver:
        driver.set_contract_from_source("con_scoping", source, owner=None)
        driver.commit()
        from xian_vm_core import execute_contract

        result = execute_contract(
            driver=driver,
            contract_name="con_scoping",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_scoping"},
            meter=False,
        )
        return result.status_code, result.result, result.writes


@pytest.mark.parametrize(
    ("case_id", "source", "expected", "fails"), CASES, ids=[case[0] for case in CASES]
)
def test_lexical_scope(tmp_path, case_id, source, expected, fails):
    status, result, writes = execute_source(tmp_path, source)
    assert status == int(fails), result
    assert writes == {}
    if fails:
        assert_failure_category(case_id, result)
    else:
        assert result == expected
