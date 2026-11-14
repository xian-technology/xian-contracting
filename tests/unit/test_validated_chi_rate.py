"""The chain chi rate rule (``chi_cost.S:value``), one implementation in Rust.

The block executor faults on a rate it cannot price fees with; admission,
genesis building and state patches refuse the same values first through
``xian_vm_core.validated_chi_rate``: a positive integer whose
``ContractingDecimal`` is representable (at most 10**61 - 1).
"""

from __future__ import annotations

from decimal import Decimal
from enum import IntEnum

import pytest
from xian_runtime_types.decimal import ContractingDecimal

xian_vm_core = pytest.importorskip("xian_vm_core")


class _Rate(IntEnum):
    TWENTY = 20


@pytest.mark.parametrize("rate", [1, 20, 2000, 10**61 - 1])
def test_a_positive_representable_integer_is_the_rate(rate):
    assert xian_vm_core.validated_chi_rate(rate) == rate
    assert type(xian_vm_core.validated_chi_rate(rate)) is int


REFUSED = [
    0,
    -5,
    10**61,
    True,
    False,
    None,
    1.5,
    "20",
    b"20",
    [20],
    {"__fixed__": "20"},
    ContractingDecimal("20"),
    Decimal("20"),
    _Rate.TWENTY,
]


@pytest.mark.parametrize("value", REFUSED, ids=[repr(value) for value in REFUSED])
def test_anything_else_is_refused_naming_the_value(value):
    with pytest.raises(ValueError) as refused:
        xian_vm_core.validated_chi_rate(value)
    assert str(refused.value) == f"chain state has no valid chi rate (chi_cost.S:value = {value!r})"
