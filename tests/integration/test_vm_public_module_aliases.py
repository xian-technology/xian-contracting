"""Safe imported aliases preserve callable identity and the original authority."""

import pytest

from tests.integration.test_vm_interface_descriptors import execute

pytestmark = pytest.mark.optional_native
TARGET = """store = Variable()
storage_alias = store
data = [1]
digest = hashlib.sha3_text
length = len
factory = bytes.fromhex
formatter = str.format_map
appender = list.append
combine = set.union
classinfo = int
info = Contract.get_info
info_again = info
info_separate = Contract.get_info
writer = store.set
bound = 'x'.upper
def hidden():
    store.set(9)
private_alias = hidden
@export
def frame(value: Any):
    return [ctx.this, ctx.caller, value]
public_alias = frame
public_again = frame
"""


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize("static", [False, True], ids=["dynamic", "static"])
def test_safe_alias_invocation_identity_and_frames(tmp_path, native, static):
    prefix = "import con_descriptor_target as module\n" if static else ""
    lookup = "" if static else "module=importlib.import_module('con_descriptor_target')\n"
    body = (
        lookup
        + """other=importlib.import_module('con_descriptor_target')
items=[]
module.appender(items, 9)
result=module.public_alias(7)
return [module.length(items), module.factory('00').hex(),
        module.formatter('{name}', {'name':'ok'}), sorted(module.combine(set([1]),[2])),
        module.classinfo('3'), result, ctx.this,
        module.public_alias is module.frame, module.public_alias is module.public_again,
        module.frame is other.frame, module.digest is other.digest,
        module.factory is bytes.fromhex, module.factory is other.factory,
        module.appender is list.append, module.combine is frozenset.union,
        module.info is module.info_again, module.info is module.info_separate,
        module.info is other.info,
        importlib.has_export(module,'public_alias')]"""
    )
    status, result, _ = execute(tmp_path, body, native=native, prefix=prefix, target=TARGET)
    assert status == 0, result
    assert result == [
        1,
        "00",
        "ok",
        [1, 2],
        3,
        ["con_descriptor_target", "con_descriptor_probe", 7],
        "con_descriptor_probe",
        True,
        True,
        False,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
    ]


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
@pytest.mark.parametrize("alias", ["data", "storage_alias", "writer", "bound", "private_alias"])
@pytest.mark.parametrize("static", [False, True], ids=["dynamic", "static"])
def test_unsafe_public_alias_is_rejected_before_arguments(tmp_path, native, alias, static):
    prefix = "import con_descriptor_target as module\n" if static else ""
    lookup = "" if static else "module=importlib.import_module('con_descriptor_target')\n"
    body = (
        lookup
        + f"""state.set('pending')
return module.{alias}(1//0)"""
    )
    status, result, writes = execute(tmp_path, body, native=native, prefix=prefix, target=TARGET)
    assert status == 1
    assert "module attribute is not an admitted public callable" in str(result)
    assert writes == {}
