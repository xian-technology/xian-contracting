"""Execution outcomes use shared domain errors, independent of an engine."""

import pytest


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (None, "success"),
        ("chi", "chi_exceeded"),
        ("call", "call_limit_exceeded"),
        ("assertion", "contract_assertion"),
        ("other", "contract_error"),
    ],
)
def test_execution_outcome_classification(kind, expected):
    from contracting.execution.errors import (
        CallLimitExceededError,
        ChiExceededError,
        classify_execution_error,
    )

    errors = {
        None: None,
        "chi": ChiExceededError("budget exhausted"),
        "call": CallLimitExceededError("instruction limit exhausted"),
        "assertion": AssertionError("contract assertion"),
        "other": ValueError("contract error"),
    }
    assert classify_execution_error(errors[kind]) == expected


def test_resource_limits_are_assertions_for_existing_failure_handling():
    from contracting.execution.errors import CallLimitExceededError, ChiExceededError

    assert isinstance(ChiExceededError("budget"), AssertionError)
    assert isinstance(CallLimitExceededError("instructions"), AssertionError)
