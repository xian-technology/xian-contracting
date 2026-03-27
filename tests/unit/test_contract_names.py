from unittest import TestCase

from contracting.names import assert_safe_contract_name, is_safe_contract_name
from contracting.storage.driver import Driver


class TestContractNames(TestCase):
    def setUp(self):
        self.driver = Driver()
        self.driver.flush_full()

    def tearDown(self):
        self.driver.flush_full()

    def test_safe_contract_name_helper_accepts_valid_names(self):
        self.assertTrue(is_safe_contract_name("submission"))
        self.assertTrue(is_safe_contract_name("con_example_2"))
        self.assertEqual(assert_safe_contract_name("con_example"), "con_example")

    def test_safe_contract_name_helper_rejects_unsafe_names(self):
        for name in (
            "",
            "Con_upper",
            "con.bad",
            "con-bad",
            "con:bad",
            "1con_bad",
            "_hidden",
        ):
            self.assertFalse(is_safe_contract_name(name))
            with self.assertRaises(AssertionError):
                assert_safe_contract_name(name)

    def test_driver_set_contract_rejects_unsafe_name(self):
        with self.assertRaises(AssertionError):
            self.driver.set_contract(
                name="con.bad",
                code="@export\ndef ping():\n    return 1\n",
            )
