"""Independent explicit expectations for the reviewed callable/value surface."""

import pytest

from tests.compatibility.runner import encode, run_case
from tests.surface.catalog import load_cases


@pytest.mark.parametrize("case", load_cases(), ids=lambda case: case["id"])
@pytest.mark.parametrize(
    "native",
    [False, pytest.param(True, marks=pytest.mark.optional_native)],
    ids=["python", "native"],
)
def test_runtime_surface_case(tmp_path, case, native):
    actual = run_case(case, tmp_path, native=native)
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == int(case.get("expected_failure", False)), actual
    assert actual["writes"] == encode({}), actual
    assert actual["events"] == encode([]), actual
    if not case.get("expected_failure", False):
        assert actual["result"] == encode(case["expected_result"]), actual
