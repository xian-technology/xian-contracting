"""Tests for the LMDB storage backend."""

import tempfile
from pathlib import Path
from unittest import TestCase

from contracting.storage.lmdb_store import LMDBStore
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime


class TestLMDBStoreBasic(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = LMDBStore(Path(self.tmpdir) / "test")

    def tearDown(self):
        self.store.close()

    def test_get_missing_key_returns_none(self):
        self.assertIsNone(self.store.get("nonexistent"))

    def test_set_and_get_round_trips_values(self):
        data = {
            "string": "value",
            "int": 42,
            "float": 3.14,
            "bool": True,
            "list": [1, 2, 3],
            "dict": {"a": 1},
            "decimal": ContractingDecimal("123.456"),
            "datetime": Datetime(2025, 3, 15, 12, 30, 0, 0),
            "bytes": b"\xde\xad\xbe\xef",
            "bytearray": bytearray(b"\xde\xad\xbe\xef"),
            "set": ContractingSet([3, 1, 3]),
            "frozenset": ContractingFrozenSet([3, 1, 3]),
        }
        self.store.batch_set(data)

        for key, value in data.items():
            self.assertEqual(self.store.get(key), value)

    def test_batch_set_none_deletes(self):
        self.store.batch_set({"key": "exists"})
        self.store.batch_set({"key": None})
        self.assertIsNone(self.store.get("key"))


class TestLMDBStoreKeys(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = LMDBStore(Path(self.tmpdir) / "test")
        self.store.batch_set(
            {
                "currency.balances:alice": 100,
                "currency.balances:bob": 200,
                "currency.__code__": "code here",
                "con_token.balances:alice": 50,
            }
        )

    def tearDown(self):
        self.store.close()

    def test_keys_prefix(self):
        self.assertEqual(
            self.store.keys("currency.balances:"),
            ["currency.balances:alice", "currency.balances:bob"],
        )

    def test_items_prefix(self):
        items = self.store.items("currency.")
        self.assertEqual(len(items), 3)
        self.assertEqual(items["currency.balances:alice"], 100)

    def test_exists(self):
        self.assertTrue(self.store.exists("currency.balances:alice"))
        self.assertFalse(self.store.exists("currency.balances:dave"))


class TestLMDBStoreDelete(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = LMDBStore(Path(self.tmpdir) / "test")
        self.store.batch_set(
            {
                "currency.balances:alice": 100,
                "currency.balances:bob": 200,
                "currency.__code__": "code",
            }
        )

    def tearDown(self):
        self.store.close()

    def test_delete_single(self):
        self.store.delete("currency.balances:alice")
        self.assertIsNone(self.store.get("currency.balances:alice"))
        self.assertEqual(self.store.get("currency.balances:bob"), 200)

    def test_delete_prefix(self):
        self.store.delete_prefix("currency.balances:")
        self.assertIsNone(self.store.get("currency.balances:alice"))
        self.assertEqual(self.store.get("currency.__code__"), "code")

    def test_flush_removes_all(self):
        self.store.flush()
        self.assertEqual(self.store.keys(), [])


class TestDriverWithLMDB(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        from contracting.storage.driver import Driver

        self.driver = Driver(storage_home=Path(self.tmpdir))

    def tearDown(self):
        self.driver.flush_full()

    def test_set_commit_get(self):
        self.driver.set_var("currency", "balances", ["alice"], value=1000)
        self.driver.commit()
        self.assertEqual(
            self.driver.get_var("currency", "balances", ["alice"]),
            1000,
        )

    def test_set_contract(self):
        source = (
            "balances = Hash(default_value=0)\n\n"
            "@export\ndef transfer(amount: float, to: str):\n    pass\n"
        )
        self.driver.set_contract_from_source("con_test", source)
        self.driver.commit()
        stored_source = self.driver.get_contract_source("con_test")
        self.assertIn("@export", stored_source)
        self.assertIn("def transfer(amount: float, to: str):", stored_source)
        self.assertIsNotNone(self.driver.get_contract("con_test"))
        self.assertIsNotNone(self.driver.get_contract_ir("con_test"))

    def test_delete_contract(self):
        self.driver.set_contract("con_test", "x = 1")
        self.driver.commit()
        self.driver.delete_contract("con_test")
        self.assertIsNone(self.driver.get_contract("con_test"))
        self.assertIsNone(self.driver.get_contract_source("con_test"))
