"""Module exposure is enforced only in authored contract execution."""

import pytest

from contracting.execution.module_access import ContractModule
from contracting.execution.runtime import _contract_execution_active
from contracting.stdlib.bridge.orm import C as Contract


def test_contract_module_preserves_trusted_host_setup():
    module = ContractModule("con_access")
    module.value = [1]
    assert module.value == [1]
    del module.value
    assert "value" not in vars(module)


def test_contract_module_filters_data_but_keeps_internal_introspection():
    module = ContractModule("con_access")
    module.value = [1]
    module.length = len
    # Sharing the approved helper class does not make its private host methods public.
    module.private_helper = Contract._submit_with_driver
    token = _contract_execution_active.set(True)
    try:
        assert module.length([1, 2]) == 2
        assert vars(module)["value"] == [1]
        assert module.__name__ == "con_access"
        with pytest.raises(AttributeError, match="not an admitted public callable"):
            _ = module.value
        with pytest.raises(AttributeError, match="not an admitted public callable"):
            _ = module.private_helper
        with pytest.raises(AttributeError, match="read-only"):
            module.length = abs
        with pytest.raises(AttributeError, match="read-only"):
            del module.length
        assert module.length is len
    finally:
        _contract_execution_active.reset(token)
