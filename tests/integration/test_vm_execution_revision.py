"""Native metadata reports the chain policy selected at the entry point."""

import json

import pytest

pytestmark = pytest.mark.optional_native


def test_native_execution_policy_defaults_to_v2_and_allows_explicit_replay():
    from xian_vm_core import runtime_info, runtime_info_json, supports_execution_policy

    info = runtime_info()
    assert info == runtime_info("xian_vm_v2") == json.loads(runtime_info_json())
    assert info["vm_profile"] == "xian_vm_v2"
    assert info["execution_revision"] == "xvm-execution-12"
    assert info["set_codec"] == "xian-set-1"
    assert info["supported_bytecode_versions"] == ["xvm-2"]
    assert info["supported_gas_schedules"] == ["xvm-gas-6"]
    assert info["max_tx_chi"] == 1_000_000
    assert supports_execution_policy("xvm-2", "xvm-gas-6")
    assert not supports_execution_policy("xvm-2", "xvm-gas-5")
    assert not supports_execution_policy("xvm-1", "xvm-gas-2")
    assert not supports_execution_policy("unknown", "xvm-gas-6")
    assert runtime_info("xian_vm_v1")["execution_revision"] == "xvm-execution-7"
    assert runtime_info("xian_vm_v1")["max_tx_chi"] == 50_000_000
    assert supports_execution_policy("xvm-1", "xvm-gas-2", "xian_vm_v1")


def test_direct_vm_host_requires_matching_storage_profile(tmp_path):
    from xian_vm_core import NativeVmHost

    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        with pytest.raises(ValueError, match="storage driver profile"):
            NativeVmHost(driver)
        assert NativeVmHost(driver, vm_profile="xian_vm_v1").driver is driver
