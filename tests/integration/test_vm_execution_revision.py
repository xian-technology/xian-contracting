"""Native metadata admits only the execution policy implemented by this build."""

import pytest

pytestmark = pytest.mark.optional_native


def test_native_execution_policy_is_explicit_and_rejects_previous_gas_schedule():
    from xian_vm_core import runtime_info, supports_execution_policy

    info = runtime_info()
    assert info["execution_revision"] == "xvm-execution-4"
    assert info["set_codec"] == "xian-set-1"
    assert info["supported_bytecode_versions"] == ["xvm-1"]
    assert info["supported_gas_schedules"] == ["xvm-gas-2"]
    assert supports_execution_policy("xvm-1", "xvm-gas-2")
    assert not supports_execution_policy("xvm-1", "xvm-gas-1")
    assert not supports_execution_policy("unknown", "xvm-gas-2")
