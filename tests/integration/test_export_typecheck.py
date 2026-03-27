from unittest import TestCase

from xian_runtime_types.decimal import ContractingDecimal

from contracting.client import ContractingClient


TYPECHECKED_CONTRACT = """
@export(typecheck=True)
def calculate(limit: float) -> str:
    return 'YES' if limit > 0.1 else 'NO'

@export(typecheck=True)
def summarize(items: list[int], metadata: dict[str, list[int]]) -> int:
    return len(items) + len(metadata['counts'])
"""


BAD_RETURN_CONTRACT = """
@export(typecheck=True)
def label(limit: float) -> str:
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
        contract = self.client.get_contract("con_typed_calc")

        self.assertEqual(contract.calculate(limit=3), "YES")
        self.assertEqual(contract.calculate(limit=0.2), "YES")
        self.assertEqual(
            contract.calculate(limit=ContractingDecimal("0.2")),
            "YES",
        )

    def test_typechecked_export_rejects_bad_argument_type(self):
        self.client.submit(TYPECHECKED_CONTRACT, name="con_typed_calc")
        contract = self.client.get_contract("con_typed_calc")

        with self.assertRaisesRegex(
            TypeError, "Argument 'limit' must be <class 'float'>"
        ):
            contract.calculate(limit="3")

    def test_typechecked_export_rejects_nested_container_mismatches(self):
        self.client.submit(TYPECHECKED_CONTRACT, name="con_typed_calc")
        contract = self.client.get_contract("con_typed_calc")

        with self.assertRaisesRegex(
            TypeError, "Argument 'metadata'\\['counts'\\]\\[1\\]"
        ):
            contract.summarize(
                items=[1, 2],
                metadata={"counts": [1, "2"]},
            )

    def test_typechecked_export_rejects_bad_return_type(self):
        self.client.submit(BAD_RETURN_CONTRACT, name="con_bad_return")
        contract = self.client.get_contract("con_bad_return")

        with self.assertRaisesRegex(
            TypeError, "Return value must be <class 'str'>"
        ):
            contract.label(limit=1)

    def test_typechecked_export_applies_to_contract_to_contract_calls(self):
        self.client.submit(INNER_TYPED_CONTRACT, name="con_inner_typed")
        self.client.submit(OUTER_TYPED_CONTRACT, name="con_outer_typed")

        outer = self.client.get_contract("con_outer_typed")

        with self.assertRaisesRegex(
            TypeError, "Argument 'count' must be <class 'int'>"
        ):
            outer.relay_bad()
