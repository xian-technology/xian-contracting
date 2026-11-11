"""Retired execution APIs must be absent from source and installed wheels."""

import importlib.util

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "contracting.execution.executor",
        "contracting.execution.module",
        "contracting.execution.python_tracer",
        "contracting.execution.tracer",
        "contracting.execution.sandbox",
        "contracting.stdlib.env",
    ],
)
def test_retired_execution_module_is_unavailable(module):
    assert importlib.util.find_spec(module) is None
