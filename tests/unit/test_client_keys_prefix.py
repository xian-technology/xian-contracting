import unittest
from contracting.client import ContractingClient


class TestClientKeysPrefix(unittest.TestCase):

    def setUp(self):
        self.client = ContractingClient()
        self.client.flush()

        # Submit two dummy contracts with similar prefixes
        code_a = """
@export
def f():
    pass
"""
        code_b = code_a
        self.client.submit(code_a, name='abc')
        self.client.submit(code_b, name='abc2')

        # Write distinct state under each contract to detect leakage
        self.client.set_var('abc', '__code__', value='X')
        self.client.set_var('abc2', '__code__', value='Y')

        # Also add a hash-like key for both
        self.client.set_var('abc', 'h', arguments=['k'], value=1)
        self.client.set_var('abc2', 'h', arguments=['k'], value=2)

    def tearDown(self):
        self.client.flush()

    def test_keys_scoped_to_exact_contract(self):
        abc = self.client.get_contract('abc')
        keys = abc.keys()
        # Ensure keys from abc2 are not present
        self.assertTrue(all(not k.startswith('abc2.') for k in keys))


if __name__ == '__main__':
    unittest.main()


