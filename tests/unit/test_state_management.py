import tempfile
from pathlib import Path
from unittest import TestCase

from contracting.client import ContractingClient

CONTRACTS_DIR = Path(__file__).resolve().parent / "contracts"


def read_contract(name: str) -> str:
    return (CONTRACTS_DIR / name).read_text(encoding="utf-8")


class TestStateManagement(TestCase):
    def setUp(self):
        self.storage_home = tempfile.TemporaryDirectory()
        self.client = ContractingClient(storage_home=self.storage_home.name)
        self.client.flush()

    def tearDown(self):
        self.client.flush()
        self.storage_home.cleanup()

    def test_ctx_this_and_caller_are_preserved_through_proxy_imports(self):
        self.client.submit(read_contract("proxythis.py"), name="con_proxythis")
        self.client.submit(read_contract("thistest2.py"), name="con_thistest2")
        proxy = self.client.get_contract("con_proxythis")

        self.assertEqual(
            proxy.proxythis(con="con_thistest2", signer="address"),
            ("con_thistest2", "con_proxythis"),
        )
        self.assertEqual(
            proxy.noproxy(signer="address"),
            ("con_proxythis", "address"),
        )
        self.assertEqual(
            proxy.nestedproxythis(con="con_thistest2", signer="address"),
            ("con_thistest2", "con_proxythis"),
        )
