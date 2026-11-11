"""Native unbound mutable methods cannot corrupt frozen dictionary keys."""

import pytest

from contracting.local import ContractingClient


@pytest.mark.parametrize(
    "call",
    [
        "set.add(value, 2)",
        "set.remove(value, 1)",
        "set.discard(value, 1)",
        "set.discard(value, 99)",
        "set.pop(value)",
        "set.clear(value)",
    ],
)
def test_authored_unbound_mutation_of_frozen_keys_is_rejected(tmp_path, call):
    source = "changed = Variable()\n@export\ndef probe():\n"
    source += "    value = frozenset([1])\n    mapping = {value: 7}\n    changed.set(99)\n"
    source += (
        f"    {call}\n    return [list(value), len(value), mapping.get(frozenset([1, 2]), 0)]\n"
    )
    with ContractingClient(storage_home=tmp_path, metering=False) as client:
        client.submit(source, name="con_frozen_keys")
        output = client.get_contract_proxy("con_frozen_keys").probe(return_full_output=True)
        assert output["status_code"] == 1, output
        assert output["writes"] == {}
        assert output["events"] == []
        assert client.raw_driver.get_var("con_frozen_keys", "changed") is None
