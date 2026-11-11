"""Authored mutation cannot change process-global Python helper objects."""

import ast
import json
import os
import subprocess
import sys

import pytest

from contracting.compilation.compiler import ContractingCompiler, guard_legacy_orm_declarations
from contracting.execution.sandbox import build_contract_builtins
from contracting.stdlib.bridge.imports import Func, Var
from contracting.stdlib.bridge.orm import V


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "statement", ["target.marker = 7", "target.marker += 1", "del target.marker"]
)
def test_non_descriptor_targets_are_rejected(legacy, statement):
    class Target:
        marker = 3

    tree = (
        ast.parse(statement)
        if legacy
        else ContractingCompiler().parse_legacy_runtime(statement, lint=False)
    )
    tree = guard_legacy_orm_declarations(tree, "con_guard")
    namespace = {"target": Target, "__builtins__": build_contract_builtins(None)}
    with pytest.raises(TypeError, match="interface descriptor"):
        exec(compile(tree, "con_guard", "exec"), namespace)
    assert Target.marker == 3


@pytest.mark.parametrize("legacy", [False, True])
def test_descriptor_targets_keep_python_order_and_single_evaluation(legacy):
    source = """
a = make('a')
b = make('b')
receiver(a, 'a').name = receiver(b, 'b').name = value('chain', 'x')
receiver(a, 'aug').name += value('aug_rhs', 'y')
(receiver(a, 'unpack_a').args, receiver(b, 'unpack_b').args) = value('unpack_rhs', (1, 2))
receiver(a, 'ann').extra: int = value('ann_rhs', 3)
del receiver(a, 'delete').extra, receiver(b, 'delete_b').args
"""
    events = []

    def receiver(value, label):
        events.append(label)
        return value

    def value(label, result):
        events.append(label)
        return result

    namespace = {
        "make": Func,
        "receiver": receiver,
        "value": value,
        "__builtins__": build_contract_builtins(None),
    }
    tree = (
        ast.parse(source)
        if legacy
        else ContractingCompiler().parse_legacy_runtime(source, lint=False)
    )
    tree = guard_legacy_orm_declarations(tree, "con_guard")
    before = ast.dump(tree)
    tree = guard_legacy_orm_declarations(tree, "con_guard")
    assert ast.dump(tree) == before
    exec(compile(tree, "con_guard", "exec"), namespace)
    assert events == [
        "chain",
        "a",
        "b",
        "aug",
        "aug_rhs",
        "unpack_rhs",
        "unpack_a",
        "unpack_b",
        "ann_rhs",
        "ann",
        "delete",
        "delete_b",
    ]
    assert namespace["a"].name == "xy"
    assert namespace["b"].name == "x"
    assert namespace["a"].args == 1
    assert not hasattr(namespace["a"], "extra")
    assert not hasattr(namespace["b"], "args")


def test_var_descriptor_fields_remain_mutable():
    value = Var("balance", V)
    tree = ContractingCompiler().parse_legacy_runtime(
        "descriptor.name = 'renamed'\ndescriptor.type = cls", lint=False
    )
    namespace = {"descriptor": value, "cls": V, "__builtins__": build_contract_builtins(None)}
    exec(compile(tree, "con_guard", "exec"), namespace)
    assert value.name == "renamed"
    assert value.type is V


PROCESS_PROBE = r"""
import json, sys
from pathlib import Path
from contracting.execution.executor import Executor
from contracting.storage.contract import Contract
from contracting.storage.driver import Driver
from contracting.stdlib.bridge.orm import C
from contracting.stdlib.bridge.imports import Func
from xian_runtime_types.time import Datetime
assignment, fail, constructor, storage = json.loads(sys.argv[1])
original = (C.submit, Func.is_of)
source = "@export\ndef hidden(value: Any = None):\n    return 731\n"
source += ("@construct\ndef seed():\n" if constructor else "@export\ndef poison():\n")
source += "    " + assignment + "\n"
source += "    assert False, 'rollback'\n" if fail else "    return True\n"
with Driver(storage_home=Path(storage), vm_profile="xian_vm_v1") as driver:
    if constructor:
        try:
            Contract(driver=driver).submit('con_poison', source)
        except Exception as exc:
            status, message = 1, str(exc)
        else:
            status, message = 0, 'accepted'
    else:
        driver.set_contract_from_source('con_poison', source, owner=None)
        driver.set_contract_from_source('con_reader', '@export\ndef read():\n    return Contract().submit()\n', owner=None)
        driver.commit()
        executor = Executor(driver=driver, metering=False)
        result = executor.execute(sender='alice', contract_name='con_poison', function_name='poison', kwargs={}, environment={'now':Datetime(2026,11,1)}, metering=False)
        status, message = result['status_code'], str(result['result'])
        reader = executor.execute(sender='alice', contract_name='con_reader', function_name='read', kwargs={}, environment={'now':Datetime(2026,11,1)}, metering=False)
        assert reader['status_code'] == 1, reader
    print(json.dumps({'status':status, 'message':message, 'unchanged':original == (C.submit, Func.is_of)}))
"""


@pytest.mark.parametrize(
    "assignment",
    [
        "Contract.submit = hidden",
        "importlib.Func.is_of = hidden",
        "hidden.marker = 7",
        "importlib.import_module.marker = 7",
    ],
)
@pytest.mark.parametrize("fail", [False, True])
@pytest.mark.parametrize("constructor", [False, True])
def test_helper_poisoning_cannot_survive_transaction_or_constructor(
    tmp_path, assignment, fail, constructor
):
    environment = dict(os.environ, HOME=str(tmp_path / "home"))
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            PROCESS_PROBE,
            json.dumps([assignment, fail, constructor, str(tmp_path / "state")]),
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    observation = json.loads(result.stdout)
    assert observation["status"] == 1, observation
    assert "interface descriptor" in observation["message"], observation
    assert observation["unchanged"], observation


def test_private_descriptor_attributes_and_subclasses_are_not_mutable():
    class Subclass(Func):
        pass

    for value, name in [(Func("x"), "_hidden"), (Subclass("x"), "name")]:
        source = f"descriptor.{name} = 1"
        tree = ContractingCompiler().parse_legacy_runtime(source, lint=False)
        with pytest.raises(TypeError):
            exec(
                compile(tree, "con_guard", "exec"),
                {"descriptor": value, "__builtins__": build_contract_builtins(None)},
            )


def test_authored_source_cannot_name_the_private_guard():
    from contracting.compilation.linter import LintingError

    with pytest.raises(LintingError):
        ContractingCompiler().parse_legacy_runtime(
            "@export\ndef probe():\n    return __xian_attribute_target__(Contract, 'submit')\n",
        )


def test_call_receiver_is_checked_once_and_guard_is_idempotent():
    class Target:
        marker = 3

    calls = []

    def factory():
        calls.append(True)
        return Target

    tree = ContractingCompiler().parse_legacy_runtime("factory().marker = 7", lint=False)
    with pytest.raises(TypeError, match="interface descriptor"):
        exec(
            compile(tree, "con_guard", "exec"),
            {"factory": factory, "__builtins__": build_contract_builtins(None)},
        )
    assert calls == [True]
    assert Target.marker == 3
    tree = ContractingCompiler().parse_legacy_runtime("target.marker = 7", lint=False)
    before = ast.dump(tree)
    assert ast.dump(guard_legacy_orm_declarations(tree, "con_guard")) == before
