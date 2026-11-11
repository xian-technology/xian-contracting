"""Interface callbacks run only for members which require interface checking."""

import pytest

from tests.integration.test_vm_interface_descriptors import execute

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize(
    ("name", "expected"), [("constant", True), ("missing", False), ("empty", False)]
)
def test_noncallable_override_is_ignored_for_unchecked_members(tmp_path, name, expected):
    body = f"""module = importlib.import_module('con_descriptor_target')
interface = importlib.Func('{name}')
interface.is_of = 7
return importlib.enforce_interface(module, [interface])"""
    status, result, writes = execute(
        tmp_path, body, target="constant=7\nempty=None\n@export\ndef noop():\n    return 1\n"
    )
    assert status == 0, result
    assert result is expected
    assert writes == {}


@pytest.mark.parametrize(("name", "expected"), [("constant", True), ("missing", False)])
def test_ignored_callback_has_no_side_effects(tmp_path, name, expected):
    body = f"""module = importlib.import_module('con_descriptor_target')
interface = importlib.Func('{name}')
interface.is_of = check
result = importlib.enforce_interface(module, [interface])
return [result, state.get()]"""
    prefix = "def check(candidate):\n    state.set('called')\n    return True\n"
    status, result, writes = execute(tmp_path, body, prefix=prefix)
    assert status == 0, result
    assert result == [expected, None]
    assert writes == {}


@pytest.mark.parametrize("kind", ["private_function", "datum"])
def test_custom_callback_cannot_receive_live_foreign_capabilities(tmp_path, kind):
    target = "balance=Variable()\ndef hidden(value):\n    balance.set(value)\n@export\ndef noop():\n    return 1\n"
    descriptor = (
        "importlib.Func('hidden', private=True)"
        if kind == "private_function"
        else "importlib.Var('balance', Variable)"
    )
    action = "candidate(9)" if kind == "private_function" else "candidate.set(9)"
    prefix = (
        f"def check(candidate):\n    state.set('callback invoked')\n    {action}\n    return True\n"
    )
    body = f"""module=importlib.import_module('con_descriptor_target')
interface={descriptor}
interface.is_of=check
state.set('pending')
return importlib.enforce_interface(module,[interface])"""
    status, result, writes = execute(tmp_path, body, prefix=prefix, target=target)
    assert status == 1
    assert "InterfaceSubject" in str(result) or "not callable" in str(result)
    assert writes == {}
