"""Metered native conditional expressions preserve both branch results."""

from decimal import Decimal

from contracting.local import ContractingClient

TERNARY_CONTRACT = """@export
def classify(limit: decimal) -> str:
    return 'YES' if limit > 0.1 else 'NO'
"""


def test_submitted_contract_ternary_executes_with_metering(tmp_path):
    with ContractingClient(storage_home=tmp_path, signer="stu", metering=True) as client:
        client.submit(TERNARY_CONTRACT, name="con_ifexp", metering=False)
        for limit, expected in [(Decimal("0.2"), "YES"), (0, "NO")]:
            output = client.executor.execute(
                sender="stu",
                contract_name="con_ifexp",
                function_name="classify",
                kwargs={"limit": limit},
                metering=True,
            )
            assert output["status_code"] == 0
            assert output["result"] == expected
            assert output["chi_used"] > 0
