"""Shared objects stay within execution; boundary failures roll back state."""

import pytest

from tests.compatibility.runner import encode, run_case

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize("sink", ["return a", "v.set(a)\n    return 1", "return str(a)"])
def test_cyclic_or_exponential_values_are_bounded(tmp_path, sink):
    body = (
        "a = []\n    a.append(a)"
        if "str" not in sink
        else "a = [1]\n    for i in range(24):\n        a = [a, a]"
    )
    output = run_case(
        {
            "id": "bounds",
            "source": "v = Variable()\n@export\ndef probe():\n    v.set(7)\n    "
            + body
            + "\n    "
            + sink
            + "\n",
        },
        tmp_path,
        native=True,
    )
    assert output["admission"] == "accepted", output
    assert output["status_code"] == 1, output
    assert output["writes"] == encode({})
    assert output["events"] == encode([])
    assert any(word in output["diagnostic"] for word in ("cyclic", "limit")), output


def test_cycles_can_be_used_and_rendered_inside_execution(tmp_path):
    output = run_case(
        {
            "id": "cycle",
            "source": "@export\ndef probe():\n    a = []\n    a.append(a)\n    return [a is a[0], a == a, str(a)]\n",
        },
        tmp_path,
        native=True,
    )
    assert output["status_code"] == 0, output
    assert output["result"] == encode([True, True, "[[...]]"])


def test_incremental_immutable_nesting_is_bounded(tmp_path):
    output = run_case(
        {
            "id": "immutable_depth",
            "source": "@export\ndef probe():\n    a = 0\n    for i in range(1000):\n        a = (a,)\n    return 1\n",
        },
        tmp_path,
        native=True,
    )
    assert output["status_code"] == 1, output
    assert "depth limit" in output["diagnostic"]
