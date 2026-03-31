import sys
from unittest import TestCase

from contracting.client import ContractingClient
from contracting.execution import runtime
from contracting.execution.tracer import DEFAULT_TRACER_MODE, create_tracer


TERNARY_CONTRACT = """
@export
def classify(limit: float) -> str:
    return 'YES' if limit > 0.1 else 'NO'
"""


class TestIfExpSupport(TestCase):
    def tearDown(self):
        runtime.rt.clean_up()
        runtime.rt.set_tracer_mode(DEFAULT_TRACER_MODE)

    def _supported_tracer_modes(self):
        yield "python_line_v1"

        if sys.version_info < (3, 12):
            return

        try:
            tracer = create_tracer("native_instruction_v1")
        except ImportError:
            return

        tracer.reset()
        yield "native_instruction_v1"

    def test_submitted_contract_ternary_executes_under_supported_tracers(self):
        for mode in self._supported_tracer_modes():
            with self.subTest(mode=mode):
                client = ContractingClient(
                    signer="stu",
                    metering=True,
                    tracer_mode=mode,
                )
                client.executor.bypass_balance_amount = True
                contract_name = f"con_ifexp_{mode}"

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
                    self.assertGreater(true_output["stamps_used"], 0)
                    self.assertEqual(false_output["status_code"], 0)
                    self.assertEqual(false_output["result"], "NO")
                    self.assertGreater(false_output["stamps_used"], 0)
                finally:
                    client.flush()
