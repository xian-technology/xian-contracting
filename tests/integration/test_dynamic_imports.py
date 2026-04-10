from unittest import TestCase
import hashlib
from xian_runtime_types.time import Datetime
from contracting.client import ContractingClient
import os


class TestDynamicImports(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(name="submission", code=contract)
        self.c.raw_driver.commit()
        self.c.submission_contract = self.c.get_contract("submission")

        # submit erc20 clone
        stubucks_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "stubucks.s.py"
        )

        with open(stubucks_path) as f:
            code = f.read()
            self.c.submit(code, name="con_stubucks")

        tejastokens_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "tejastokens.s.py"
        )

        with open(tejastokens_path) as f:
            code = f.read()
            self.c.submit(code, name="con_tejastokens")

        bastardcoin_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "bastardcoin.s.py"
        )

        with open(bastardcoin_path) as f:
            code = f.read()
            self.c.submit(code, name="con_bastardcoin")

        dynamic_importing_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "dynamic_importing.s.py",
        )

        with open(dynamic_importing_path) as f:
            code = f.read()
            self.c.submit(code, name="con_dynamic_importing")

        dynamic_ctx_probe_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "dynamic_ctx_probe.s.py",
        )

        with open(dynamic_ctx_probe_path) as f:
            code = f.read()
            self.c.submit(code, name="con_dynamic_ctx_probe")

        self.stubucks = self.c.get_contract("con_stubucks")
        self.tejastokens = self.c.get_contract("con_tejastokens")
        self.bastardcoin = self.c.get_contract("con_bastardcoin")
        self.dynamic_importing = self.c.get_contract("con_dynamic_importing")
        self.dynamic_ctx_probe = self.c.get_contract("con_dynamic_ctx_probe")

    def tearDown(self):
        self.c.raw_driver.flush_full()

    def test_successful_submission(self):
        self.assertEqual(self.stubucks.balance_of(account="stu"), 123)
        self.assertEqual(self.stubucks.balance_of(account="colin"), 321)

        self.assertEqual(self.tejastokens.balance_of(account="stu"), 321)
        self.assertEqual(self.tejastokens.balance_of(account="colin"), 123)

        self.assertEqual(self.bastardcoin.balance_of(account="stu"), 999)
        self.assertEqual(self.bastardcoin.balance_of(account="colin"), 555)

    def test_get_stubuck_balances(self):
        stu = self.dynamic_importing.balance_for_token(
            tok="con_stubucks", account="stu"
        )
        colin = self.dynamic_importing.balance_for_token(
            tok="con_stubucks", account="colin"
        )

        self.assertEqual(stu, 123)
        self.assertEqual(colin, 321)

    def test_dynamic_call_by_contract_name(self):
        stu = self.dynamic_importing.dynamic_balance_for_token(
            tok="con_stubucks",
            function_name="balance_of",
            account="stu",
        )
        colin = self.dynamic_importing.dynamic_balance_for_token(
            tok="con_stubucks",
            function_name="balance_of",
            account="colin",
        )

        self.assertEqual(stu, 123)
        self.assertEqual(colin, 321)

    def test_exists_by_contract_name(self):
        self.assertTrue(
            self.dynamic_importing.contract_exists(tok="con_stubucks")
        )
        self.assertTrue(
            self.dynamic_importing.contract_exists(tok="con_dynamic_importing")
        )

    def test_exists_by_module_object(self):
        self.assertTrue(
            self.dynamic_importing.contract_exists_module(tok="con_stubucks")
        )
        self.assertTrue(
            self.dynamic_importing.contract_exists_module(
                tok="con_dynamic_importing"
            )
        )

    def test_exists_returns_false_for_missing_or_invalid_contract(self):
        self.assertFalse(
            self.dynamic_importing.contract_exists(tok="con_missing")
        )
        self.assertFalse(self.dynamic_importing.contract_exists(tok="con-bad"))
        self.assertFalse(self.dynamic_importing.contract_exists(tok="hashlib"))

    def test_has_export_by_contract_name(self):
        self.assertTrue(
            self.dynamic_importing.contract_has_export(
                tok="con_stubucks", function_name="balance_of"
            )
        )
        self.assertTrue(
            self.dynamic_importing.contract_has_export(
                tok="con_dynamic_importing",
                function_name="dynamic_balance_for_token",
            )
        )

    def test_has_export_by_module_object(self):
        self.assertTrue(
            self.dynamic_importing.contract_has_export_module(
                tok="con_tejastokens", function_name="balance_of"
            )
        )

    def test_has_export_returns_false_for_missing_or_invalid_targets(self):
        self.assertFalse(
            self.dynamic_importing.contract_has_export(
                tok="con_missing", function_name="balance_of"
            )
        )
        self.assertFalse(
            self.dynamic_importing.contract_has_export(
                tok="con_stubucks", function_name="balance-of"
            )
        )
        self.assertFalse(
            self.dynamic_importing.contract_has_export(
                tok="con_stubucks", function_name="__balances"
            )
        )
        self.assertFalse(
            self.dynamic_importing.contract_has_export(
                tok="con_dynamic_importing", function_name="enforce_erc20"
            )
        )

    def test_dynamic_call_by_module_object(self):
        stu = self.dynamic_importing.dynamic_balance_for_token_module(
            tok="con_tejastokens",
            function_name="balance_of",
            account="stu",
        )
        colin = self.dynamic_importing.dynamic_balance_for_token_module(
            tok="con_tejastokens",
            function_name="balance_of",
            account="colin",
        )

        self.assertEqual(stu, 321)
        self.assertEqual(colin, 123)

    def test_dynamic_call_rejects_private_name(self):
        with self.assertRaises(AssertionError):
            self.dynamic_importing.dynamic_private_call(
                tok="con_stubucks",
                function_name="__balances",
            )

    def test_dynamic_call_rejects_non_export_function(self):
        with self.assertRaises(AssertionError):
            self.dynamic_importing.dynamic_non_export_call(
                tok="con_dynamic_importing",
                function_name="enforce_erc20",
            )

    def test_dynamic_call_rejects_bad_kwargs(self):
        with self.assertRaises(AssertionError):
            self.dynamic_importing.dynamic_call_with_bad_kwargs(
                tok="con_stubucks",
                function_name="balance_of",
            )

    def test_dynamic_call_preserves_owner_checks(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(
                code,
                name="con_owner_for_dynamic",
                owner="con_dynamic_importing",
            )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(
                code,
                name="con_owner_forbidden_dynamic",
                owner="poot",
            )

        value = self.dynamic_importing.dynamic_owner_call(
            tok="con_owner_for_dynamic"
        )
        self.assertEqual(value, "con_dynamic_importing")

        with self.assertRaises(Exception):
            self.dynamic_importing.dynamic_owner_call(
                tok="con_owner_forbidden_dynamic"
            )

    def test_dynamic_call_preserves_ctx_semantics(self):
        result = self.dynamic_importing.dynamic_ctx_call(
            tok="con_dynamic_ctx_probe",
            account="stu",
        )

        self.assertEqual(
            result,
            {
                "caller": "con_dynamic_importing",
                "signer": "stu",
                "this": "con_dynamic_ctx_probe",
                "entry": "con_dynamic_importing.dynamic_ctx_call",
                "account": "stu",
            },
        )

    def test_executor_reports_nested_contract_costs(self):
        self.c.executor.bypass_balance_amount = True
        output = self.c.executor.execute(
            sender="stu",
            contract_name="con_dynamic_importing",
            function_name="dynamic_balance_for_token",
            kwargs={
                "tok": "con_stubucks",
                "function_name": "balance_of",
                "account": "stu",
            },
            metering=True,
        )

        self.assertEqual(output["status_code"], 0)
        self.assertEqual(output["result"], 123)
        self.assertIn("con_dynamic_importing", output["contract_costs"])
        self.assertIn("con_stubucks", output["contract_costs"])
        self.assertGreater(output["contract_costs"]["con_dynamic_importing"], 0)
        self.assertGreater(output["contract_costs"]["con_stubucks"], 0)
        self.assertEqual(
            sum(output["contract_costs"].values()) // 1000,
            output["chi_used"],
        )

    def test_get_tejastokens_balances(self):
        stu = self.dynamic_importing.balance_for_token(
            tok="con_tejastokens", account="stu"
        )
        colin = self.dynamic_importing.balance_for_token(
            tok="con_tejastokens", account="colin"
        )

        self.assertEqual(stu, 321)
        self.assertEqual(colin, 123)

    def test_get_bastardcoin_balances(self):
        stu = self.dynamic_importing.balance_for_token(
            tok="con_bastardcoin", account="stu"
        )
        colin = self.dynamic_importing.balance_for_token(
            tok="con_bastardcoin", account="colin"
        )

        self.assertEqual(stu, 999)
        self.assertEqual(colin, 555)

    def test_is_erc20(self):
        self.assertTrue(
            self.dynamic_importing.is_erc20_compatible(tok="con_stubucks")
        )
        self.assertTrue(
            self.dynamic_importing.is_erc20_compatible(tok="con_tejastokens")
        )
        self.assertFalse(
            self.dynamic_importing.is_erc20_compatible(tok="con_bastardcoin")
        )

    def test_is_erc20_by_contract_name(self):
        self.assertTrue(
            self.dynamic_importing.is_erc20_compatible_name(
                tok="con_stubucks"
            )
        )
        self.assertTrue(
            self.dynamic_importing.is_erc20_compatible_name(
                tok="con_tejastokens"
            )
        )
        self.assertFalse(
            self.dynamic_importing.is_erc20_compatible_name(
                tok="con_bastardcoin"
            )
        )

    def test_get_balances_erc20_enforced_stubucks(self):
        stu = self.dynamic_importing.only_erc20(
            tok="con_stubucks", account="stu"
        )
        colin = self.dynamic_importing.only_erc20(
            tok="con_stubucks", account="colin"
        )

        self.assertEqual(stu, 123)
        self.assertEqual(colin, 321)

    def test_get_balances_erc20_enforced_tejastokens(self):
        stu = self.dynamic_importing.only_erc20(
            tok="con_tejastokens", account="stu"
        )
        colin = self.dynamic_importing.only_erc20(
            tok="con_tejastokens", account="colin"
        )

        self.assertEqual(stu, 321)
        self.assertEqual(colin, 123)

    def test_erc20_enforced_fails_for_bastardcoin(self):
        with self.assertRaises(AssertionError):
            stu = self.dynamic_importing.only_erc20(
                tok="con_bastardcoin", account="stu"
            )

    def test_owner_of_returns_default(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poo")

        owner_stuff = self.c.get_contract("con_owner_stuff")

        self.assertIsNone(owner_stuff.get_owner(s="con_stubucks", signer="poo"))
        self.assertEqual(
            owner_stuff.get_owner(s="con_owner_stuff", signer="poo"), "poo"
        )
        self.assertIsNone(
            owner_stuff.get_owner_by_name(s="con_stubucks", signer="poo")
        )
        self.assertEqual(
            owner_stuff.get_owner_by_name(s="con_owner_stuff", signer="poo"),
            "poo",
        )

    def test_contract_info_returns_runtime_metadata(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poo")

        owner_stuff = self.c.get_contract("con_owner_stuff")
        expected = {
            "name": "con_owner_stuff",
            "owner": "poo",
            "developer": self.c.get_var("con_owner_stuff", "__developer__"),
            "deployer": self.c.get_var("con_owner_stuff", "__deployer__"),
            "initiator": self.c.get_var("con_owner_stuff", "__initiator__"),
            "submitted": self.c.get_var("con_owner_stuff", "__submitted__"),
        }

        self.assertEqual(
            owner_stuff.get_contract_info(
                s="con_owner_stuff",
                signer="poo",
            ),
            expected,
        )

    def test_code_hash_returns_runtime_and_source_hashes(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poo")

        owner_stuff = self.c.get_contract("con_owner_stuff")
        runtime_code = self.c.get_var("con_owner_stuff", "__code__")
        source_code = self.c.get_var("con_owner_stuff", "__source__")
        expected_runtime_hash = hashlib.sha3_256(
            runtime_code.encode("utf-8")
        ).hexdigest()
        expected_source_hash = hashlib.sha3_256(
            source_code.encode("utf-8")
        ).hexdigest()

        self.assertEqual(
            owner_stuff.get_code_hash(
                s="con_owner_stuff",
                kind="runtime",
                signer="poo",
            ),
            expected_runtime_hash,
        )
        self.assertEqual(
            owner_stuff.get_code_hash_by_name(
                s="con_owner_stuff",
                kind="runtime",
                signer="poo",
            ),
            expected_runtime_hash,
        )
        self.assertEqual(
            owner_stuff.get_code_hash(
                s="con_owner_stuff",
                kind="source",
                signer="poo",
            ),
            expected_source_hash,
        )
        self.assertEqual(
            owner_stuff.get_code_hash_by_name(
                s="con_owner_stuff",
                kind="source",
                signer="poo",
            ),
            expected_source_hash,
        )

    def test_code_hash_rejects_invalid_kind(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poo")

        owner_stuff = self.c.get_contract("con_owner_stuff")

        with self.assertRaises(AssertionError):
            owner_stuff.get_code_hash_by_name(
                s="con_owner_stuff",
                kind="compiled",
                signer="poo",
            )

    def test_ctx_owner_works(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poot")

        owner_stuff = self.c.get_contract("con_owner_stuff")

        self.assertEqual(owner_stuff.owner_of_this(signer="poot"), "poot")

    def test_incorrect_owner_prevents_function_call(self):
        owner_stuff_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "owner_stuff.s.py"
        )

        with open(owner_stuff_path) as f:
            code = f.read()
            self.c.submit(code, name="con_owner_stuff", owner="poot")

        owner_stuff = self.c.get_contract("owner_stuff")
        with self.assertRaises(Exception):
            owner_stuff.owner_of_this()

    def test_delegate_call_with_owner_works(self):
        parent_test_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "parent_test.s.py"
        )

        with open(parent_test_path) as f:
            code = f.read()
            self.c.submit(code, name="con_parent_test")

        child_test_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "child_test.s.py"
        )

        with open(child_test_path) as f:
            code = f.read()
            self.c.submit(code, name="con_child_test", owner="con_parent_test")

        parent_test = self.c.get_contract("con_parent_test")

        val = parent_test.get_val_from_child(s="con_child_test")

        self.assertEqual(val, "good")

    def test_delegate_with_wrong_owner_does_not_work(self):
        parent_test_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "parent_test.s.py"
        )

        with open(parent_test_path) as f:
            code = f.read()
            self.c.submit(code, name="con_parent_test")

        child_test_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "child_test.s.py"
        )

        with open(child_test_path) as f:
            code = f.read()
            self.c.submit(code, name="con_child_test", owner="blorg")

        parent_test = self.c.get_contract("parent_test")

        with self.assertRaises(Exception) as e:
            parent_test.get_val_from_child(s="child_test")
