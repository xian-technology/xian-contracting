import os
from unittest import TestCase

from contracting.constants import CHI_PER_T
from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


def submission_kwargs_for_file(f):
    # Get the file name only by splitting off directories
    split = f.split("/")
    split = split[-1]

    # Now split off the .s
    split = split.split(".")
    contract_name = split[0]

    with open(f) as file:
        contract_code = file.read()

    return {
        "name": f"con_{contract_name}",
        "code": contract_code,
    }


TEST_SUBMISSION_KWARGS = {
    "sender": "stu",
    "contract_name": "submission",
    "function_name": "submit_contract",
}


class TestMetering(TestCase):
    def setUp(self):
        # Hard load the submission contract
        self.d = Driver()
        self.d.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.d.set_contract(name="submission", code=contract)
        self.d.commit()

        # Execute the currency contract with metering disabled
        self.e = Executor(driver=self.d, currency_contract="con_currency")
        currency_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "currency.s.py"
        )
        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs=submission_kwargs_for_file(currency_path),
            metering=False,
            auto_commit=True,
        )

    def tearDown(self):
        self.d.flush_full()

    def test_simple_execution_deducts_chi(self):
        prior_balance = self.d.get("con_currency.balances:stu")

        output = self.e.execute(
            "stu",
            "con_currency",
            "transfer",
            kwargs={"amount": 100, "to": "colin"},
            auto_commit=True,
        )

        new_balance = self.d.get("con_currency.balances:stu")

        self.assertEqual(
            float(prior_balance - new_balance - 100),
            output["chi_used"] / CHI_PER_T,
        )

    def test_too_few_chi_fails_and_deducts_properly(self):
        prior_balance = self.d.get("con_currency.balances:stu")

        print(prior_balance)

        output = self.e.execute(
            "stu",
            "con_currency",
            "transfer",
            kwargs={"amount": 100, "to": "colin"},
            chi=1,
            auto_commit=True,
        )

        print(output)

        new_balance = self.d.get("con_currency.balances:stu")

        self.assertEqual(
            float(prior_balance - new_balance),
            output["chi_used"] / CHI_PER_T,
        )

    def test_adding_too_many_chi_throws_error(self):
        prior_balance = self.d.get("con_currency.balances:stu")
        too_many_chi = (prior_balance + 1000) * CHI_PER_T

        output = self.e.execute(
            "stu",
            "con_currency",
            "transfer",
            kwargs={"amount": 100, "to": "colin"},
            chi=too_many_chi,
            auto_commit=True,
        )

        self.assertEqual(output["status_code"], 1)

    def test_adding_all_chi_with_infinate_loop_eats_all_balance(self):
        self.d.set("con_currency.balances:stu", 500)
        self.d.commit()

        prior_balance = self.d.get("con_currency.balances:stu")

        prior_balance *= CHI_PER_T

        inf_loop_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "inf_loop.s.py"
        )

        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs=submission_kwargs_for_file(inf_loop_path),
            chi=prior_balance,
            metering=True,
            auto_commit=True,
        )

        new_balance = self.d.get("con_currency.balances:stu")

        # Not all chi will be deducted because it will blow up in the middle of execution

        self.assertTrue(new_balance < 500)

    def test_submitting_contract_succeeds_with_enough_chi(self):
        prior_balance = self.d.get("con_currency.balances:stu")

        print(prior_balance)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )
        output = self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs=submission_kwargs_for_file(erc20_clone_path),
            auto_commit=True,
        )
        print(output)

        new_balance = self.d.get("con_currency.balances:stu")

        print(new_balance)

        self.assertEqual(
            float(prior_balance - new_balance),
            output["chi_used"] / CHI_PER_T,
        )

    def test_string_balance_value_is_metered_correctly(self):
        small_code = """@export
def get():
    return 'a'
"""
        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs={"name": "con_string_balance_probe", "code": small_code},
            metering=False,
            auto_commit=True,
        )

        self.d.set("con_currency.balances:stu", "100000")
        self.d.commit()

        output = self.e.execute(
            "stu",
            "con_string_balance_probe",
            "get",
            kwargs={},
            auto_commit=True,
        )

        new_balance = self.d.get("con_currency.balances:stu")

        self.assertEqual(output["status_code"], 0)
        self.assertLess(new_balance, 100000)

    def test_string_balance_value_allows_contract_submission(self):
        self.d.set("con_currency.balances:stu", "100000")
        self.d.commit()

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )
        output = self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs=submission_kwargs_for_file(erc20_clone_path),
            auto_commit=True,
        )

        self.assertEqual(output["status_code"], 0)

    def test_pending_writes_has_deducted_stamp_amount_prior_to_auto_commit(
        self,
    ):
        prior_balance = self.d.get("con_currency.balances:stu")

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )
        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs=submission_kwargs_for_file(erc20_clone_path),
            auto_commit=False,
        )
        self.assertNotEqual(
            self.e.driver.pending_writes["con_currency.balances:stu"],
            prior_balance,
        )

    def test_larger_return_values_cost_more_chi(self):
        small_code = """@export
def get():
    return 'a'
"""
        large_code = """@export
def get():
    return 'a' * 4096
"""

        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs={"name": "con_small_return", "code": small_code},
            metering=False,
            auto_commit=True,
        )
        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs={"name": "con_large_return", "code": large_code},
            metering=False,
            auto_commit=True,
        )

        small_output = self.e.execute(
            "stu",
            "con_small_return",
            "get",
            kwargs={},
        )
        large_output = self.e.execute(
            "stu",
            "con_large_return",
            "get",
            kwargs={},
        )

        self.assertGreater(
            large_output["chi_used"], small_output["chi_used"]
        )

    def test_excessively_large_return_value_fails(self):
        huge_code = """@export
def get():
    return 'a' * (1024 * 128 + 1)
"""

        self.e.execute(
            **TEST_SUBMISSION_KWARGS,
            kwargs={"name": "con_huge_return", "code": huge_code},
            metering=False,
            auto_commit=True,
        )

        output = self.e.execute(
            "stu",
            "con_huge_return",
            "get",
            kwargs={},
        )

        self.assertEqual(output["status_code"], 1)
