import os
from datetime import datetime
from hashlib import sha3_256, sha256
from unittest import TestCase

from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient
from contracting.local.native_executor import NativeExecutor
from tests.integration.contract_fixtures import SUBMIT_CONTRACT, submission_kwargs_for_file


class TestComplexContracts(TestCase):
    def setUp(self):
        self.client = ContractingClient(signer="stu", metering=False)
        self.addCleanup(self.client.close)
        self.d = self.client.raw_driver

    def test_token_construction_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        currency_path = os.path.join(os.path.dirname(__file__), "test_contracts", "currency.s.py")

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(currency_path))

        res = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "colin"},
        )

        self.assertEqual(res["result"], 100)

        res = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "stu"},
        )
        self.assertEqual(res["result"], 1000000)

        res = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "raghu"},
        )
        self.assertEqual(res["result"], None)

    def test_token_transfer_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        currency_path = os.path.join(os.path.dirname(__file__), "test_contracts", "currency.s.py")

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(currency_path))

        e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="transfer",
            kwargs={"amount": 1000, "to": "colin"},
        )

        stu_balance = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "stu"},
        )
        colin_balance = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "colin"},
        )

        self.assertEqual(stu_balance["result"], 1000000 - 1000)
        self.assertEqual(colin_balance["result"], 100 + 1000)

    def test_token_transfer_failure_not_enough_to_send(self):
        e = NativeExecutor(driver=self.d, metering=False)

        currency_path = os.path.join(os.path.dirname(__file__), "test_contracts", "currency.s.py")

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(currency_path))

        status = e.execute(
            sender="stu",
            contract_name="currency",
            function_name="transfer",
            kwargs={"amount": 1000001, "to": "colin"},
        )

        self.assertEqual(status["status_code"], 1)

    def test_token_transfer_to_new_account(self):
        e = NativeExecutor(driver=self.d, metering=False)

        currency_path = os.path.join(os.path.dirname(__file__), "test_contracts", "currency.s.py")

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(currency_path))

        e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="transfer",
            kwargs={"amount": 1000, "to": "raghu"},
        )

        raghu_balance = e.execute(
            sender="stu",
            contract_name="con_currency",
            function_name="balance",
            kwargs={"account": "raghu"},
        )

        self.assertEqual(raghu_balance["result"], 1000)

    def test_erc20_clone_construction_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        stu = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "stu"},
        )
        colin = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "colin"},
        )
        supply = e.execute(
            sender="stu", contract_name="con_erc20_clone", function_name="total_supply", kwargs={}
        )

        self.assertEqual(stu["result"], 1000000)
        self.assertEqual(colin["result"], 100)
        self.assertEqual(supply["result"], 1000100)

    def test_erc20_clone_transfer_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="transfer",
            kwargs={"amount": 1000000, "to": "raghu"},
        )
        raghu = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "raghu"},
        )
        stu = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "stu"},
        )

        self.assertEqual(raghu["result"], 1000000)
        self.assertEqual(stu["result"], 0)

    def test_erc20_clone_transfer_fails(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        output = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="transfer",
            kwargs={"amount": 10000000, "to": "raghu"},
        )

        self.assertEqual(output["status_code"], 1)
        # breakpoint()
        self.assertEqual(str(output["result"]), "Not enough coins to send!")

    def test_allowance_of_blank(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        output = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="allowance",
            kwargs={"owner": "stu", "spender": "raghu"},
        )
        self.assertEqual(output["result"], 0)

    def test_approve_works_and_allowance_shows(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="approve",
            kwargs={"amount": 1234, "to": "raghu"},
        )

        output = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="allowance",
            kwargs={"owner": "stu", "spender": "raghu"},
        )
        self.assertEqual(output["result"], 1234)

    def test_approve_and_transfer_from(self):
        e = NativeExecutor(driver=self.d, metering=False)

        erc20_clone_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "erc20_clone.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(erc20_clone_path))

        e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="approve",
            kwargs={"amount": 1234, "to": "raghu"},
        )
        e.execute(
            sender="raghu",
            contract_name="con_erc20_clone",
            function_name="transfer_from",
            kwargs={"amount": 123, "to": "tejas", "main_account": "stu"},
        )
        raghu = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "raghu"},
        )
        stu = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "stu"},
        )
        tejas = e.execute(
            sender="stu",
            contract_name="con_erc20_clone",
            function_name="balance_of",
            kwargs={"account": "tejas"},
        )

        self.assertEqual(raghu["result"], 0)
        self.assertEqual(stu["result"], (1000000 - 123))
        self.assertEqual(tejas["result"], 123)

    def test_failure_after_data_writes_doesnt_commit(self):
        e = NativeExecutor(driver=self.d, metering=False)

        leaky_path = os.path.join(os.path.dirname(__file__), "test_contracts", "leaky.s.py")

        e.execute(
            **SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(leaky_path), auto_commit=True
        )

        e.execute(
            sender="colin",
            contract_name="con_leaky",
            function_name="transfer",
            kwargs={"amount": 1234, "to": "raghu"},
            auto_commit=True,
        )

        raghu = e.execute(
            sender="stu",
            contract_name="con_leaky",
            function_name="balance_of",
            kwargs={"account": "raghu"},
            auto_commit=True,
        )
        colin = e.execute(
            sender="stu",
            contract_name="con_leaky",
            function_name="balance_of",
            kwargs={"account": "colin"},
            auto_commit=True,
        )

        self.assertEqual(raghu["result"], 0)
        self.assertEqual(colin["result"], 100)

    def test_leaky_contract_commits_on_success(self):
        e = NativeExecutor(driver=self.d, metering=False)

        leaky_path = os.path.join(os.path.dirname(__file__), "test_contracts", "leaky.s.py")

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(leaky_path))

        e.execute(
            sender="colin",
            contract_name="con_leaky",
            function_name="transfer",
            kwargs={"amount": 1, "to": "raghu"},
        )

        raghu = e.execute(
            sender="stu",
            contract_name="con_leaky",
            function_name="balance_of",
            kwargs={"account": "raghu"},
        )
        colin = e.execute(
            sender="stu",
            contract_name="con_leaky",
            function_name="balance_of",
            kwargs={"account": "colin"},
        )

        self.assertEqual(raghu["result"], 1)
        self.assertEqual(colin["result"], 99)

    def test_time_stdlib_works(self):
        e = NativeExecutor(driver=self.d, metering=False)
        now = datetime.now()

        environment = {}
        date = Datetime(now.year, now.month, now.day)
        environment.update({"now": date})

        time_path = os.path.join(os.path.dirname(__file__), "test_contracts", "time.s.py")

        res = e.execute(
            **SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(time_path), environment=environment
        )
        self.assertEqual(res["status_code"], 0, res["result"])

        gt = e.execute(
            sender="colin",
            contract_name="con_time",
            function_name="gt",
            kwargs={},
            environment=environment,
        )
        self.assertTrue(gt["result"])

        lt = e.execute(
            sender="colin",
            contract_name="con_time",
            function_name="lt",
            kwargs={},
            environment=environment,
        )
        self.assertFalse(lt["result"])

        eq = e.execute(
            sender="colin",
            contract_name="con_time",
            function_name="eq",
            kwargs={},
            environment=environment,
        )
        self.assertFalse(eq["result"])

    def test_bad_time_contract_not_submittable(self):
        e = NativeExecutor(driver=self.d, metering=False)
        now = datetime.now()

        environment = {}
        date = Datetime(now.year, now.month, now.day)
        environment.update({"now": date})

        bad_time_path = os.path.join(os.path.dirname(__file__), "test_contracts", "bad_time.s.py")

        output = e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(bad_time_path),
            environment=environment,
        )
        self.assertEqual(output["status_code"], 1)
        self.assertIn(
            "Name '_datetime' must not start or end with underscore",
            str(output["result"]),
        )

    def test_json_lists_work(self):
        e = NativeExecutor(driver=self.d, metering=False)

        json_tests_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "json_tests.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(json_tests_path))

        res = e.execute(
            sender="colin", contract_name="con_json_tests", function_name="get_some", kwargs={}
        )

        self.assertListEqual([1, 2, 3, 4], res["result"])

    def test_time_storage_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        time_storage_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "time_storage.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(time_storage_path))

        v = e.execute(
            sender="colin", contract_name="con_time_storage", function_name="get", kwargs={}
        )

        date = Datetime(2019, 1, 1)

        self.assertEqual(v["result"], date)

    def test_hash_sha3_text_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        hashing_works_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "hashing_works.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(hashing_works_path))

        secret = "c0d1cc254c2aca8716c6ef170630550d"
        s3 = e.execute(
            sender="colin",
            contract_name="con_hashing_works",
            function_name="t_sha3_text",
            kwargs={"s": secret},
        )

        h = sha3_256()
        h.update(secret.encode("utf-8"))
        self.assertEqual(h.hexdigest(), s3["result"])

    def test_hash_sha3_hex_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        hashing_works_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "hashing_works.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(hashing_works_path))

        secret = "c0d1cc254c2aca8716c6ef170630550d"
        s3 = e.execute(
            sender="colin",
            contract_name="con_hashing_works",
            function_name="t_sha3_hex",
            kwargs={"s": secret},
        )

        h = sha3_256()
        h.update(bytes.fromhex(secret))
        self.assertEqual(h.hexdigest(), s3["result"])

    def test_hash_sha256_text_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_hashing_works_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "hashing_works.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(test_hashing_works_path))

        secret = "c0d1cc254c2aca8716c6ef170630550d"
        s3 = e.execute(
            sender="colin",
            contract_name="con_hashing_works",
            function_name="t_sha256_text",
            kwargs={"s": secret},
        )

        h = sha256()
        h.update(secret.encode("utf-8"))
        self.assertEqual(h.hexdigest(), s3["result"])

    def test_hash_sha256_hex_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_hashing_works_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "hashing_works.s.py"
        )

        e.execute(**SUBMIT_CONTRACT, kwargs=submission_kwargs_for_file(test_hashing_works_path))

        secret = "c0d1cc254c2aca8716c6ef170630550d"
        s3 = e.execute(
            sender="colin",
            contract_name="con_hashing_works",
            function_name="t_sha256_hex",
            kwargs={"s": secret},
        )

        h = sha256()
        h.update(bytes.fromhex(secret))
        self.assertEqual(h.hexdigest(), s3["result"])
