from decimal import Decimal
from unittest import TestCase

from contracting.local import ContractingClient

TYPECHECKED_CONTRACT = """
@export(typecheck=True)
def calculate(limit: decimal) -> str:
    return 'YES' if limit > 0.1 else 'NO'

@export(typecheck=True)
def summarize(items: list[int], metadata: dict[str, list[int]]) -> int:
    return len(items) + len(metadata['counts'])
"""


BAD_RETURN_CONTRACT = """
@export(typecheck=True)
def label(limit: decimal) -> str:
    return 123
"""


INNER_TYPED_CONTRACT = """
@export(typecheck=True)
def double(count: int) -> int:
    return count * 2
"""


OUTER_TYPED_CONTRACT = """
import con_inner_typed

@export
def relay_bad():
    return con_inner_typed.double(count='3')
"""


class TestExportTypecheck(TestCase):
    def setUp(self):
        self.client = ContractingClient(signer="stu")
        self.client.flush()

    def tearDown(self):
        self.client.flush()

    def test_typechecked_export_accepts_decimal_backed_numeric_values(self):
        self.client.submit(TYPECHECKED_CONTRACT, name="con_typed_calc")
        contract = self.client.get_contract_proxy("con_typed_calc")

        self.assertEqual(contract.calculate(limit=3), "YES")
        self.assertEqual(contract.calculate(limit=Decimal("0.2")), "YES")
        with self.assertRaises(TypeError):
            contract.calculate(limit=0.2)

    def test_typechecked_export_rejects_bad_argument_type(self):
        self.client.submit(TYPECHECKED_CONTRACT, name="con_typed_calc")
        contract = self.client.get_contract_proxy("con_typed_calc")

        with self.assertRaisesRegex(TypeError, "ABI value must be <class 'decimal'>, got str"):
            contract.calculate(limit="3")

    def test_typechecked_export_rejects_nested_container_mismatches(self):
        self.client.submit(TYPECHECKED_CONTRACT, name="con_typed_calc")
        contract = self.client.get_contract_proxy("con_typed_calc")

        with self.assertRaisesRegex(TypeError, "ABI value must be <class 'int'>, got str"):
            contract.summarize(
                items=[1, 2],
                metadata={"counts": [1, "2"]},
            )

    def test_typechecked_export_rejects_bad_return_type(self):
        self.client.submit(BAD_RETURN_CONTRACT, name="con_bad_return")
        contract = self.client.get_contract_proxy("con_bad_return")

        with self.assertRaisesRegex(TypeError, "Return value must be <class 'str'>"):
            contract.label(limit=1)

    def test_typechecked_export_applies_to_contract_to_contract_calls(self):
        self.client.submit(INNER_TYPED_CONTRACT, name="con_inner_typed")
        self.client.submit(OUTER_TYPED_CONTRACT, name="con_outer_typed")

        outer = self.client.get_contract_proxy("con_outer_typed")

        with self.assertRaisesRegex(TypeError, "ABI value must be <class 'int'>, got str"):
            outer.relay_bad()
