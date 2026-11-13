import unittest
from unittest.mock import Mock

from contracting.storage.driver import Driver


class TestDriver(unittest.TestCase):

    def setUp(self):
        # Setup a fresh instance of Driver and ensure a clean storage environment
        self.driver = Driver()
        self.driver.flush_full()

    def tearDown(self):
        # Clean up any state that might affect other tests
        self.driver.flush_full()

    def test_set_and_get(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.commit()
        retrieved_value = self.driver.get(key)
        self.assertEqual(retrieved_value, value)

    def test_find(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.commit()
        retrieved_value = self.driver.find(key)
        self.assertEqual(retrieved_value, value)

    def test_find_respects_pending_writes(self):
        driver = Driver()
        driver.flush_full()
        try:
            driver.set("pending_key", "pending_value")
            self.assertEqual(driver.find("pending_key"), "pending_value")
        finally:
            driver.flush_full()

    def test_keys_from_disk(self):
        key1 = 'test_key1'
        key2 = 'test_key2'
        value = 'test_value'
        self.driver.set(key1, value)
        self.driver.set(key2, value)
        self.driver.commit()
        keys = self.driver.keys_from_disk()
        self.assertIn(key1, keys)
        self.assertIn(key2, keys)

    def test_iter_from_disk(self):
        key1 = 'test_key1'
        key2 = 'test_key2'
        prefix_key = 'prefix_key'
        value = 'test_value'
        self.driver.set(key1, value)
        self.driver.set(key2, value)
        self.driver.set(prefix_key, value)
        self.driver.commit()
        keys = self.driver.iter_from_disk(prefix=prefix_key)
        self.assertIn(prefix_key, keys)
        self.assertNotIn(key1, keys)
        self.assertNotIn(key2, keys)

    def test_scan_keys_from_disk_paginates_prefix_results(self):
        for suffix in ("alice", "bob", "carol"):
            self.driver.set(f"currency.balances:{suffix}", "1")
        self.driver.commit()

        first_page, first_has_more = self.driver.scan_keys_from_disk(
            "currency.balances",
            limit=2,
        )
        second_page, second_has_more = self.driver.scan_keys_from_disk(
            "currency.balances",
            limit=2,
            after_key=first_page[-1],
        )

        self.assertEqual(
            first_page,
            [
                "currency.balances:alice",
                "currency.balances:bob",
            ],
        )
        self.assertTrue(first_has_more)
        self.assertEqual(second_page, ["currency.balances:carol"])
        self.assertFalse(second_has_more)

    def test_items(self):
        prefix_key = 'prefix_key'
        value = 'test_value'
        self.driver.set(prefix_key, value)
        self.driver.commit()
        items = self.driver.items(prefix=prefix_key)
        self.assertIn(prefix_key, items)
        self.assertEqual(items[prefix_key], value)

    def test_delete_key_from_disk(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.commit()
        self.driver.delete_key_from_disk(key)
        retrieved_value = self.driver.value_from_disk(key)
        self.assertIsNone(retrieved_value)

    def test_flush_cache(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.flush_cache()
        self.assertFalse(self.driver.pending_items())

    def test_flush_disk(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.commit()
        self.driver.flush_disk()
        self.assertFalse(self.driver.get(key))

    def test_commit(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        self.driver.commit()
        retrieved_value = self.driver.get(key)
        self.assertEqual(retrieved_value, value)

    def test_commit_skips_store_write_transaction_when_empty(self):
        self.driver._store.commit_overlay = Mock()

        self.driver.commit()

        self.driver._store.commit_overlay.assert_not_called()

    def test_get_all_contract_state(self):
        key = 'contract.key'
        value = 'contract_value'
        self.driver.set(key, value)
        self.driver.commit()
        contract_state = self.driver.get_all_contract_state()
        self.assertIn(key, contract_state)
        self.assertEqual(contract_state[key], value)

    def test_transaction_writes(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value, is_txn_write=True)
        # self.driver.commit()
        transaction_writes = self.driver.transaction_writes
        self.assertIn(key, transaction_writes)
        self.assertEqual(transaction_writes[key], value)

    def test_clear_transaction_writes(self):
        key = 'test_key'
        value = 'test_value'
        self.driver.set(key, value)
        # self.driver.commit()
        self.driver.clear_transaction_writes()
        transaction_writes = self.driver.transaction_writes
        self.assertNotIn(key, transaction_writes)

    def test_get_run_state(self):
        # We can't test this function here since we are not running a real blockchain.
        pass

    def _populate_pending_state(self):
        self.driver.set('con_thing.balances:alice', 10, is_txn_write=True)
        self.driver.get('con_thing.balances:bob')
        self.driver.keys_from_disk('con_thing.')
        self.driver.set_event({'event': 'Transfer'})

    def _pending(self):
        return {
            'writes': self.driver.pending_items(),
            'transaction_writes': dict(self.driver.transaction_writes),
            'log_events': list(self.driver.log_events),
        }

    def test_snapshot_state_restores_exact_state(self):
        self._populate_pending_state()
        expected = self._pending()
        snapshot = self.driver.snapshot_state()

        self.driver.set('con_other.thing', 'junk')
        self.driver.log_events.append({'event': 'Junk'})
        self.driver.keys_from_disk('con_other.')
        self.driver.restore_state(snapshot)

        self.assertEqual(self._pending(), expected)

    def test_snapshot_state_supports_repeated_restores(self):
        self._populate_pending_state()
        expected = self._pending()
        snapshot = self.driver.snapshot_state()

        self.driver.restore_state(snapshot)
        self.driver.log_events.append({'event': 'Junk'})
        self.driver.set('con_other.thing', 'junk')
        self.driver.restore_state(snapshot)

        self.assertEqual(self._pending(), expected)

    def test_restore_state_none_is_noop(self):
        self._populate_pending_state()
        expected = self._pending()
        self.driver.restore_state(None)
        self.assertEqual(self._pending(), expected)

    def test_detach_pending_state_leaves_an_empty_driver(self):
        self._populate_pending_state()

        self.driver.detach_pending_state()

        self.assertEqual(
            self._pending(),
            {
                'writes': [],
                'transaction_writes': {},
                'log_events': [],
            },
        )

    def test_attach_pending_state_discards_interim_mutations(self):
        self._populate_pending_state()
        expected = self._pending()
        detached = self.driver.detach_pending_state()

        self.driver.set('con_interim.thing', 'junk')
        self.driver.log_events.append({'event': 'Interim'})
        self.driver.attach_pending_state(detached)

        self.assertEqual(self._pending(), expected)

    def test_detach_attach_round_trip_preserves_commit(self):
        self.driver.set('con_thing.balances:alice', 25)

        detached = self.driver.detach_pending_state()
        self.driver.attach_pending_state(detached)
        self.driver.commit()

        self.assertEqual(self.driver.value_from_disk('con_thing.balances:alice'), 25)
        self.assertEqual(self.driver.pending_items(), [])
