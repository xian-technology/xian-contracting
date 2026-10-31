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


@pytest.mark.parametrize("mutate", [False, True])
def test_sort_callback_observes_empty_list_and_rejects_mutation(tmp_path, mutate):
    source = (
        "VALUES = [3, 1, 2]\n"
        "def key(value):\n"
        + ("    VALUES.append(9)\n" if mutate else "")
        + "    return len(VALUES)\n"
        "@export\ndef probe():\n"
        "    VALUES.sort(key=key)\n"
        "    return VALUES\n"
    )
    output = run_case({"id": "sort_callback", "source": source}, tmp_path, native=True)
    assert output["admission"] == "accepted", output
    if mutate:
        assert output["status_code"] == 1, output
        assert "modified during sort" in output["diagnostic"]
        assert output["writes"] == encode({})
    else:
        assert output["status_code"] == 0, output
        assert output["result"] == encode([3, 1, 2])


@pytest.mark.parametrize("native", [False, True])
def test_round_extreme_integer_digits_returns_zero_without_large_allocation(tmp_path, native):
    output = run_case(
        {
            "id": "round_limit",
            "source": "@export\ndef probe():\n    return round(123, -(10**50))\n",
        },
        tmp_path,
        native=native,
    )
    assert output["status_code"] == 0, output
    assert output["result"] == encode(0)
