"""Typed interface descriptors preserve Python values without becoming stored data."""

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

TARGET = """balance = Variable()
ledger = Hash()
constant = 7
@export
def transfer(amount: int, to: str):
    return amount
@export
def noop():
    return 1
@export
def mutate(value: Any):
    value.name = 'changed'
    return value
@export
def inspect_var(value: Any):
    return [isinstance(value, importlib.Var), value.type is Variable]
@export
def make():
    return importlib.Func('transfer', ('amount','to'))
@export
def inject(value: Any):
    value.extra = abs
    return 1
def hidden(value):
    return value
"""


def execute(home, body, *, native=True, meter=False, prefix="", target=TARGET):
    source = (
        prefix
        + "state = Variable()\n@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_descriptor_target", target, owner=None)
        driver.set_contract_from_source("con_descriptor_probe", source, owner=None)
        driver.commit()
        if native:
            from xian_vm_core import execute_contract

            result = execute_contract(
                driver=driver,
                contract_name="con_descriptor_probe",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_descriptor_probe"},
                meter=meter,
            )
            return result.status_code, result.result, result.writes
        result = Executor(driver=driver, metering=False).execute(
            sender="alice",
            contract_name="con_descriptor_probe",
            function_name="probe",
            kwargs={},
            metering=False,
        )
        return result["status_code"], result["result"], result["writes"]


NOMINAL = [
    (
        "func_fields",
        "f = importlib.Func('x', ('a','b'), private=True)\nreturn [f.name, list(f.args)]",
        ["__x", ["a", "b"]],
    ),
    ("name_exact", "return importlib.Func(7).name", 7),
    (
        "args_identity",
        "args = []\nf = importlib.Func('x', args)\nargs.append('a')\nreturn [f.args is args, f.args]",
        [True, ["a"]],
    ),
    (
        "func_class",
        "factory = importlib.Func\nf = factory('x')\nreturn [isinstance(f,factory),isinstance(f,dict),isinstance({},factory),issubclass(factory,importlib.Var)]",
        [True, False, False, False],
    ),
    (
        "var_class",
        "v = importlib.Var('balance', Variable)\nreturn [v.name,v.type is Variable,isinstance(v,importlib.Var),isinstance(v,dict)]",
        ["__balance", True, True, False],
    ),
    (
        "mutable_extras",
        "f = importlib.Func('wrong')\nf.name = 'probe'\nf.extra = 2\nf.extra += 3\nreturn [f.is_of(probe),f.extra]",
        [True, 5],
    ),
    (
        "bound_receiver_mutation",
        "f = importlib.Func('wrong')\ncheck = f.is_of\nf.name = 'probe'\nreturn check(probe)",
        True,
    ),
    (
        "tuple_list_exact",
        "return [importlib.Func('probe').is_of(probe),importlib.Func('probe',[]).is_of(probe)]",
        [True, False],
    ),
    (
        "identity_dictionary",
        "a = importlib.Func('x')\nb = importlib.Func('x')\nvalues = {a:1,b:2}\na.name = 'y'\nreturn [a==a,a==b,a is b,len(values),values[a],values[b]]",
        [True, False, False, 2, 1, 2],
    ),
    ("self_cycle", "f = importlib.Func('x')\nf.next = f\nreturn f.next is f", True),
    (
        "var_is_of",
        "v = importlib.Var('state',Variable)\nreturn [v.is_of(state),v.is_of(1)]",
        [True, False],
    ),
    (
        "var_type_mutable",
        "v = importlib.Var('x',Variable)\nv.type = (int,str)\nreturn [v.is_of(1),v.is_of('x'),v.is_of([])]",
        [True, True, False],
    ),
    (
        "func_bound_function",
        "f = importlib.Func('x')\nv = importlib.Var('x',Variable)\nreturn [importlib.Func('is_of',('self','f')).is_of(f.is_of),importlib.Func('is_of',('self','v')).is_of(v.is_of)]",
        [True, True],
    ),
    (
        "kwargs_methods",
        "return [importlib.Func('probe').is_of(f=probe),importlib.Var('state',Variable).is_of(v=state)]",
        [True, True],
    ),
    (
        "interface",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func('transfer',('amount','to')),importlib.Var('balance',Variable)])",
        True,
    ),
    (
        "interface_list",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func('transfer',['amount','to'])])",
        False,
    ),
    (
        "interface_private",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func('hidden',('value',),private=True)])",
        True,
    ),
    (
        "interface_constant",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func('constant')])",
        True,
    ),
    (
        "cross_mutation",
        "m = importlib.import_module('con_descriptor_target')\nf = importlib.Func('x')\nother = m.mutate(f)\nreturn [other is f,f.name]",
        [True, "changed"],
    ),
    (
        "cross_var",
        "m = importlib.import_module('con_descriptor_target')\nreturn m.inspect_var(importlib.Var('balance',Variable))",
        [True, True],
    ),
    (
        "cross_return",
        "m = importlib.import_module('con_descriptor_target')\nf = m.make()\nreturn [f.name,list(f.args),isinstance(f,importlib.Func)]",
        ["transfer", ["amount", "to"], True],
    ),
    (
        "imported_is_of",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.Func('transfer',('amount','to')).is_of(m.transfer)",
        True,
    ),
]


NOMINAL.extend(
    [
        (
            "var_identity_dictionary",
            "a = importlib.Var('x',Variable)\nb = importlib.Var('x',Variable)\nvalues = {a:1,b:2}\na.name = 'y'\nreturn [a==b,len(values),values[a],values[b]]",
            [False, 2, 1, 2],
        ),
        (
            "cross_cycle",
            "m = importlib.import_module('con_descriptor_target')\nf = importlib.Func('x')\nf.next = f\nother = m.mutate(f)\nreturn [other is f,other.next is f,f.name]",
            [True, True, "changed"],
        ),
        ("method_override", "f = importlib.Func('x')\nf.is_of = bool\nreturn f.is_of(1)", True),
    ]
)


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize(("case", "body", "expected"), NOMINAL, ids=[case[0] for case in NOMINAL])
def test_descriptor_values(tmp_path, native, case, body, expected):
    status, result, _ = execute(tmp_path, body, native=native)
    assert status == 0, (case, result)
    assert result == expected


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize(
    "body",
    [
        "state.set(1)\nstate.set([importlib.Func('x')])\nreturn 0",
        "state.set(1)\nreturn {'value':importlib.Var('x',Variable)}",
        "state.set(1)\nf = importlib.Func('x')\nf.next = f\nreturn f",
        "state.set(1)\nm = importlib.import_module('con_descriptor_target')\nf = importlib.Func('x')\nf.capability = abs\nreturn m.mutate(f)",
        "state.set(1)\nm = importlib.import_module('con_descriptor_target')\nv = importlib.Var('x',Variable)\nv.type = int\nreturn m.mutate(v)",
        "state.set(1)\nm = importlib.import_module('con_descriptor_target')\nf = importlib.Func('x')\nm.inject(f)\nreturn 0",
    ],
)
def test_descriptor_boundaries_reject_and_roll_back(tmp_path, meter, body):
    status, result, writes = execute(tmp_path, body, meter=meter)
    assert status == 1, result
    assert "cannot cross" in str(result)
    assert writes == {}


@pytest.mark.parametrize(
    "body",
    [
        "return importlib.Func('x').private",
        "return importlib.Var(1,Variable)",
        "return importlib.Func('x').is_of(1)",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[{'__vm_interface__':'func','name':'noop','args':()}])",
        "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func([])])",
    ],
)
@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_descriptor_invalid_inputs(tmp_path, body, native):
    status, _, writes = execute(tmp_path, body, native=native)
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_descriptor_argument_metadata_and_single_attribute_receiver_evaluation(tmp_path, native):
    prefix = """seen = Variable(default_value=0)
def choose(value):
    seen.set(seen.get()+1)
    return value
@export
def target(x: int, y: int=1, *, z: int=2):
    return x+y+z
"""
    body = "f = importlib.Func('target',('x','y'))\nf.extra = 1\nf.values = [1]\nchoose(f).extra += 2\nchoose(f).values[0] += 4\nreturn [f.is_of(target),f.extra,f.values,seen.get()]"
    status, result, _ = execute(tmp_path, body, native=native, prefix=prefix)
    assert status == 0, result
    assert result == [True, 3, [5], 2]


@pytest.mark.parametrize(
    "body",
    [
        "return importlib.Func('x',name='y')",
        "return importlib.Func('x',unknown=1)",
        "return importlib.Func('x',(),False,1)",
        "return importlib.Var('x')",
        "return importlib.Var('x',Variable,t=Hash)",
    ],
)
@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_descriptor_constructor_binding(tmp_path, body, native):
    status, _, writes = execute(tmp_path, body, native=native)
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_builtin_interface_callback_can_inspect_inert_subject_truthiness(tmp_path, native):
    body = "state.set(1)\nm = importlib.import_module('con_descriptor_target')\nf = importlib.Func('noop')\nf.is_of = bool\nreturn importlib.enforce_interface(m,[f])"
    status, result, writes = execute(tmp_path, body, native=native)
    assert status == 0, result
    assert result is True
    assert writes == {"con_descriptor_probe.state": 1}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_log_event_is_inert_descriptor_type_metadata(tmp_path, native):
    prefix = "event = LogEvent('Event', {'value': int})\n"
    body = "v = importlib.Var('event', LogEvent)\nreturn [v.type is LogEvent,v.is_of(event)]"
    status, result, _ = execute(tmp_path, body, native=native, prefix=prefix)
    assert status == 0, result
    assert result == [True, True]


@pytest.mark.parametrize(
    "declarations", ["constant = None", "constant = 7\nconstant = None", "constant = [] or None"]
)
@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_interface_observes_initialized_none_globals(tmp_path, declarations, native):
    target = declarations + "\n@export\ndef noop():\n    return 1\n"
    body = "m = importlib.import_module('con_descriptor_target')\nreturn importlib.enforce_interface(m,[importlib.Func('constant')])"
    status, result, _ = execute(tmp_path, body, native=native, target=target)
    assert status == 0, result
    assert result is False


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_interface_self_and_reentrant_caller_use_live_metadata(tmp_path, native):
    target = "@export\ndef inspect_caller():\n    return importlib.enforce_interface(importlib.import_module(ctx.caller),[importlib.Func('constant')])\n"
    body = "m = importlib.import_module('con_descriptor_target')\nreturn [importlib.enforce_interface(importlib.import_module(ctx.this),[importlib.Func('constant')]),m.inspect_caller()]"
    status, result, _ = execute(
        tmp_path, body, native=native, prefix="constant = None\n", target=target
    )
    assert status == 0, result
    assert result == [False, False]


def test_circular_interface_initialization_fails_and_next_execution_recovers(tmp_path):
    from xian_vm_core import execute_contract

    first = """ready = importlib.enforce_interface(importlib.import_module('con_cycle_b'), [importlib.Func('probe')])
@export
def probe():
    return 1
"""
    second = first.replace("con_cycle_b", "con_cycle_a")
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_cycle_a", first, owner=None)
        driver.set_contract_from_source("con_cycle_b", second, owner=None)
        driver.set_contract_from_source(
            "con_after_cycle", "@export\ndef probe():\n    return 7\n", owner=None
        )
        driver.commit()
        for contract, success in [("con_cycle_a", False), ("con_after_cycle", True)]:
            result = execute_contract(
                driver=driver,
                contract_name=contract,
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": contract},
                meter=True,
            )
            assert result.status_code == (0 if success else 1), result.result
            assert result.writes == {}
            if success:
                assert result.result == 7
            else:
                assert "circular module initialization" in str(result.result)
