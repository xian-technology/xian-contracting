"""Retired execution APIs must be absent from source and installed wheels."""

import importlib.util

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "contracting.execution.executor",
        "contracting.execution.module",
        "contracting.execution.parallel",
        "contracting.execution.python_tracer",
        "contracting.execution.tracer",
        "contracting.execution.sandbox",
        "contracting.stdlib.env",
    ],
)
def test_retired_execution_module_is_unavailable(module):
    assert importlib.util.find_spec(module) is None


def test_local_client_exposes_no_parallel_batch_executor():
    from contracting.local import ContractingClient

    assert not hasattr(ContractingClient, "build_parallel_executor")


def test_the_block_overlay_keeps_no_read_tracking():
    import inspect

    from xian_vm_core import BlockState

    from contracting.storage.driver import Driver

    retired_driver_api = {
        "transaction_access",
        "set_transaction_read_tracking",
        "clear_transaction_reads",
        "track_transaction_reads",
    }
    retired_overlay_api = {
        "tracking",
        "set_tracking",
        "record_read",
        "record_prefix",
        "access",
        "clear_access",
    }
    assert retired_driver_api.isdisjoint(dir(Driver))
    assert retired_overlay_api.isdisjoint(dir(BlockState))
    assert "save" not in inspect.signature(Driver.get).parameters
    assert "mark" not in inspect.signature(Driver.get_var).parameters
