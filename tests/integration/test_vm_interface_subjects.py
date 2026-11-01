"""Custom interface predicates receive immutable metadata, never target objects."""

import pytest

from tests.integration.test_vm_interface_descriptors import execute

pytestmark = pytest.mark.optional_native

CASES = [
    (
        "function",
        """def check(subject):
    state.set([subject.kind, subject.name, subject.args, subject.storage_type, ctx.this, ctx.caller])
    return importlib.Func('transfer', ('amount', 'to')).is_of(subject)
""",
        "importlib.Func('transfer')",
        [True, ["function", "transfer", ("amount", "to"), None, "con_descriptor_probe", "alice"]],
    ),
    (
        "storage",
        """def check(subject):
    state.set([subject.kind, subject.name, subject.args, subject.storage_type])
    return importlib.Var('balance', Variable).is_of(subject)
""",
        "importlib.Var('balance', Variable)",
        [True, ["storage", "__balance", None, "Variable"]],
    ),
    ("falsey", "def check(subject):\n    return []\n", "importlib.Func('transfer')", [False, None]),
    ("truthy", "def check(subject):\n    return [0]\n", "importlib.Func('transfer')", [True, None]),
    (
        "wrong_matcher",
        "def check(subject):\n    return importlib.Var('balance',Variable).is_of(subject)\n",
        "importlib.Func('transfer')",
        [False, None],
    ),
]


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize("name,prefix,descriptor,expected", CASES, ids=[case[0] for case in CASES])
def test_custom_interface_subject(tmp_path, native, name, prefix, descriptor, expected):
    body = f"""module=importlib.import_module('con_descriptor_target')
interface={descriptor}
interface.is_of=check
result=importlib.enforce_interface(module,[interface])
return [result,state.get()]"""
    status, result, _ = execute(tmp_path, body, native=native, prefix=prefix)
    assert status == 0, result

    # Storage codecs may normalize tuple payloads; metadata is explicitly a tuple
    # before storing it, as the default Func predicate verifies independently.
    def normalized(value):
        return [normalized(item) for item in value] if isinstance(value, (list, tuple)) else value

    assert normalized(result) == normalized(expected)


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize(
    "action",
    [
        'subject.name="changed"',
        "subject.set(9)",
        "subject(9)",
        'raise Exception("predicate failed")',
    ],
)
def test_subject_errors_rollback(tmp_path, native, action):
    prefix = f'def check(subject):\n    state.set("pending")\n    {action}\n    return True\n'
    body = """module=importlib.import_module('con_descriptor_target')
interface=importlib.Func('hidden',private=True)
interface.is_of=check
return importlib.enforce_interface(module,[interface])"""
    status, result, writes = execute(tmp_path, body, native=native, prefix=prefix)
    assert status == 1, result
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize(
    "action,expected", [("append", [True, 2]), ("remove", [True, 1]), ("replace", [False, 1])]
)
def test_interface_predicates_observe_live_descriptor_iteration(tmp_path, native, action, expected):
    mutation = {
        "append": "if len(interfaces) == 1:\n        following=importlib.Func('noop')\n        following.is_of=check\n        interfaces.append(following)",
        "remove": "interfaces.pop()",
        "replace": "interfaces[1] = importlib.Func('missing')",
    }[action]
    prefix = f"""interfaces=[]
calls=[]
def check(subject):
    calls.append(subject.name)
    {mutation}
    return True
"""
    second = (
        ""
        if action == "append"
        else f"interfaces.append(importlib.Func('{'missing' if action == 'remove' else 'noop'}'))"
    )
    body = f"""first=importlib.Func('transfer')
first.is_of=check
interfaces.append(first)
{second}
result=importlib.enforce_interface(importlib.import_module('con_descriptor_target'),interfaces)
return [result,len(calls)]"""
    status, result, _ = execute(tmp_path, body, native=native, prefix=prefix)
    assert status == 0, result
    assert result == expected
