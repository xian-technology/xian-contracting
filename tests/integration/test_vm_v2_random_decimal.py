"""``random.random()`` in V2: an exact decimal on the 30-digit grid.

Python's ``random()`` returns a 53-bit float; Xian's returns
``randbelow(10**30) / 10**30``, drawn from the transaction's random stream
like ``randrange(10**30)``, so it is usable wherever a decimal is.
"""

from decimal import ROUND_FLOOR, Decimal

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from tests.integration.test_vm_v2_numeric_boundaries import call

pytestmark = pytest.mark.optional_native

GRID = 10**30


def test_random_is_randrange_of_the_grid_over_the_grid():
    result = call(
        "@export\ndef probe():\n"
        "    random.seed('salt')\n    drawn = random.random()\n"
        "    random.seed('salt')\n    return [drawn, random.randrange(10**30)]"
    )
    assert result.status_code == 0, result.result
    drawn, scaled = result.result
    assert type(drawn) is ContractingDecimal
    assert 0 <= scaled < GRID
    assert drawn._scaled == scaled


def test_random_is_usable_wherever_a_decimal_is():
    result = call(
        "stored = Variable()\n"
        "@export\ndef probe():\n"
        "    random.seed()\n    r = random.random()\n    stored.set(r)\n"
        "    return [r, 0 <= r, r < 1, r + 1, r * 2, r - r, int(r), int(r * 10**30),\n"
        "            stored.get() == r, str(r) == str(stored.get()), max(r, 0.5) >= r,\n"
        "            quantize(r, 2, 'floor'), isinstance(r, decimal)]"
    )
    assert result.status_code == 0, result.result
    r, *rest = result.result
    assert type(r) is ContractingDecimal
    assert rest == [
        True,
        True,
        r + 1,
        r * 2,
        0,
        0,
        r._scaled,
        True,
        True,
        True,
        ContractingDecimal(Decimal(str(r)).quantize(Decimal("0.01"), rounding=ROUND_FLOOR)),
        True,
    ]
    assert len(result.writes) == 1
    assert list(result.writes.values()) == [r]


def test_draws_cover_the_unit_interval_and_differ():
    result = call(
        "@export\ndef probe():\n"
        "    random.seed()\n    return [random.random() for i in range(64)]"
    )
    assert result.status_code == 0, result.result
    draws = result.result
    assert all(type(r) is ContractingDecimal and 0 <= r < 1 for r in draws)
    assert len(set(str(r) for r in draws)) == 64
    assert min(draws) < ContractingDecimal("0.25") and max(draws) > ContractingDecimal("0.75")
