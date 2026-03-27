from unittest import TestCase

from contracting.names import validate_contract_name
from contracting.storage.driver import Driver


class TestContractNameValidation(TestCase):
    def setUp(self):
        self.driver = Driver()
        self.driver.flush_full()

    def tearDown(self):
        self.driver.flush_full()

    def test_validate_contract_name_accepts_ascii_identifier_names(self):
        for name in (
            "submission",
            "currency",
            "zk_registry",
            "con_counter",
            "con_token_v2",
            "module1",
        ):
            self.assertEqual(validate_contract_name(name), name)

    def test_validate_contract_name_rejects_special_characters(self):
        for name in ("con-test", "con.test", "con:test", "con test"):
            with self.assertRaisesRegex(
                AssertionError,
                "lowercase ASCII letters, digits, and underscores",
            ):
                validate_contract_name(name)

    def test_validate_contract_name_rejects_non_identifier_prefixes(self):
        for name in ("", "1contract", "_contract", "Con_token"):
            with self.assertRaises(AssertionError):
                validate_contract_name(name)

    def test_driver_set_contract_rejects_invalid_name(self):
        with self.assertRaisesRegex(
            AssertionError,
            "lowercase ASCII letters, digits, and underscores",
        ):
            self.driver.set_contract("con.test", "x = 1")

    def test_driver_set_contract_from_source_rejects_invalid_name(self):
        source = """@export
def ping():
    return 1
"""

        with self.assertRaisesRegex(
            AssertionError,
            "lowercase ASCII letters, digits, and underscores",
        ):
            self.driver.set_contract_from_source("con:test", source)
