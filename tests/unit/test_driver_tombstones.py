import unittest
from contracting.storage.driver import Driver


class TestDriverTombstones(unittest.TestCase):

    def setUp(self):
        self.driver = Driver(bypass_cache=False)
        self.driver.flush_full()

    def tearDown(self):
        self.driver.flush_full()

    def test_items_excludes_pending_deletes(self):
        key = 'con.hash:subkey'
        self.driver.set(key, 'v1')
        # Persist first so value exists on disk
        self.driver.commit()
        # Now set tombstone in the same transaction context
        self.driver.set(key, None)

        items = self.driver.items(prefix='con.hash:')
        keys = self.driver.keys(prefix='con.hash:')
        values = self.driver.values(prefix='con.hash:')

        self.assertNotIn(key, items)
        self.assertNotIn(key, keys)
        self.assertEqual(values, [])


if __name__ == '__main__':
    unittest.main()


