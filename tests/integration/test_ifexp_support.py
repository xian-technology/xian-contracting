from unittest import TestCase

from contracting.execution import runtime
from contracting.local import ContractingClient

TERNARY_CONTRACT = """
@export
def classify(limit: float) -> str:
    return 'YES' if limit > 0.1 else 'NO'
"""


class TestIfExpSupport(TestCase):
    def tearDown(self):
        runtime.rt.clean_up()

    def test_submitted_contract_ternary_executes_with_metering(self):
        client = ContractingClient(signer="stu", metering=True)
        client.executor.bypass_balance_amount = True
        contract_name = "con_ifexp"

        try:
            client.flush()
            client.submit(
                TERNARY_CONTRACT,
                name=contract_name,
                metering=False,
            )

            true_output = client.executor.execute(
                sender="stu",
                contract_name=contract_name,
                function_name="classify",
                kwargs={"limit": 0.2},
                metering=True,
            )
            false_output = client.executor.execute(
                sender="stu",
                contract_name=contract_name,
                function_name="classify",
                kwargs={"limit": 0.0},
                metering=True,
            )

            self.assertEqual(true_output["status_code"], 0)
            self.assertEqual(true_output["result"], "YES")
            self.assertGreater(true_output["chi_used"], 0)
            self.assertEqual(false_output["status_code"], 0)
            self.assertEqual(false_output["result"], "NO")
            self.assertGreater(false_output["chi_used"], 0)
        finally:
            client.flush()
