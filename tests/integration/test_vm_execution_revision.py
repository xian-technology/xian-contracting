"""Native metadata reports the chain policy selected at the entry point."""

import json

import pytest

pytestmark = pytest.mark.optional_native


def test_native_execution_policy_is_v2_only():
    from xian_vm_core import runtime_info, runtime_info_json, supports_execution_policy

    info = runtime_info()
    assert info == runtime_info("xian_vm_v2") == json.loads(runtime_info_json())
    assert info["vm_profile"] == "xian_vm_v2"
    assert info["execution_revision"] == "xvm-execution-14"
    assert info["set_codec"] == "xian-set-1"
    assert info["tx_admission_revision"] == "xian-fastpath-admission-3"
    assert info["supported_bytecode_versions"] == ["xvm-2"]
    assert info["supported_gas_schedules"] == ["xvm-gas-6"]
    assert info["max_tx_chi"] == 1_000_000
    assert supports_execution_policy("xvm-2", "xvm-gas-6")
    assert not supports_execution_policy("xvm-2", "xvm-gas-5")
    assert not supports_execution_policy("xvm-1", "xvm-gas-2")
    assert not supports_execution_policy("unknown", "xvm-gas-6")
    # V1 execution was removed from current code (it replays on its pinned release).
    with pytest.raises(ValueError, match="unknown VM profile"):
        runtime_info("xian_vm_v1")
    assert not supports_execution_policy("xvm-1", "xvm-gas-2", "xian_vm_v1")
