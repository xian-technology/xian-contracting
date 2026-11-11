import os
from unittest import TestCase

import pytest

from contracting.local import ContractingClient
from contracting.local.native_executor import NativeExecutor
from tests.integration.contract_fixtures import SUBMIT_CONTRACT, submission_kwargs_for_file


class TestNativeExecutor(TestCase):
    def setUp(self):
        self.client = ContractingClient(signer="stu", metering=False)
        self.addCleanup(self.client.close)
        self.d = self.client.raw_driver

    def test_submission(self):
        from contracting.artifacts import compile_contract_source

        source = "@export\ndef d():\n    return 1\n"
        output = self.client.executor.execute(
            **SUBMIT_CONTRACT,
            kwargs={"name": "con_stubucks", "code": source},
            auto_commit=True,
        )
        self.assertEqual(output["status_code"], 0, output["result"])
        expected = compile_contract_source(module_name="con_stubucks", source=source)
        self.assertEqual(self.d.get_contract_source("con_stubucks"), expected["source"])
        self.assertEqual(self.d.get_contract_ir("con_stubucks"), expected["vm_ir_json"])

    def test_submission_then_function_call(self):
        e = NativeExecutor(driver=self.d, metering=False)

        code = """@export
def d():
    return 1            
"""

        kwargs = {
            "name": "con_stubuckz",
            "code": code,
        }

        e.execute(**SUBMIT_CONTRACT, kwargs=kwargs)
        output = e.execute(
            sender="stu",
            contract_name="con_stubuckz",
            function_name="d",
            kwargs={},
        )

        self.assertEqual(output["result"], 1)
        self.assertEqual(output["status_code"], 0)

    def test_submission_rejects_unsafe_contract_name(self):
        e = NativeExecutor(driver=self.d, metering=False)

        code = """@export
def ping():
    return 1
"""

        for bad_name in (
            "con_bad-name",
            "con_bad.name",
            "con_bad:name",
            "con_bad name",
        ):
            output = e.execute(
                **SUBMIT_CONTRACT,
                kwargs={
                    "name": bad_name,
                    "code": code,
                },
            )

            self.assertEqual(output["status_code"], 1)
            self.assertIn(
                "lowercase ASCII letters, digits, and underscores",
                str(output["result"]),
            )
            self.assertIsNone(self.d.get_contract_source(bad_name))

    def test_submission_rejects_invalid_owner_type(self):
        e = NativeExecutor(driver=self.d, metering=False)

        code = """@export
def ping():
    return 1
"""

        output = e.execute(
            **SUBMIT_CONTRACT,
            kwargs={
                "name": "con_valid_name",
                "code": code,
                "owner": 7,
            },
        )

        self.assertEqual(output["status_code"], 1)
        self.assertIsNone(self.d.get_contract_source("con_valid_name"))

    def test_change_developer_rejects_empty_string(self):
        e = NativeExecutor(driver=self.d, metering=False)

        code = """@export
def ping():
    return 1
"""

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs={
                "name": "con_valid_name",
                "code": code,
            },
            auto_commit=True,
        )

        output = e.execute(
            sender="stu",
            contract_name="submission",
            function_name="change_developer",
            kwargs={"contract": "con_valid_name", "new_developer": ""},
        )

        self.assertEqual(output["status_code"], 1)
        self.assertEqual(
            self.d.get_var("con_valid_name", "__developer__"),
            "stu",
        )

    def test_kwarg_helper(self):
        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )

        k = submission_kwargs_for_file(test_orm_variable_contract_path)

        code = """v = Variable()

@export
def set_v(i: int):
    v.set(i)

@export
def get_v():
    return v.get()
"""

        self.assertEqual(k["name"], "con_orm_variable_contract")
        self.assertEqual(
            k["code"].strip(),
            code.strip(),
        )

    def test_orm_variable_sets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_variable_contract_path),
            auto_commit=True,
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="set_v",
            kwargs={"i": 1000},
            auto_commit=True,
        )

        i = self.d.get("con_orm_variable_contract.v")
        self.assertEqual(i, 1000)

    def test_orm_variable_gets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_variable_contract_path),
        )

        res = e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="get_v",
            kwargs={},
        )

        self.assertEqual(res["result"], None)

    def test_orm_variable_gets_and_sets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_variable_contract_path),
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="set_v",
            kwargs={"i": 1000},
        )
        res = e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="get_v",
            kwargs={},
        )

        self.assertEqual(res["result"], 1000)

    def test_orm_variable_collection_helpers_work_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        code = """settings = Variable(default_value={})
queue = Variable(default_value=[])

@export
def set_setting(key: str, value: int):
    values = settings.get()
    values[key] = value
    settings.set(values)

@export
def get_settings():
    return settings.get()

@export
def enqueue(value: int):
    queue.append(value)

@export
def replace_first(value: int):
    values = queue.get()
    values[0] = value
    queue.set(values)

@export
def get_queue():
    return queue.get()
"""

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs={
                "name": "con_variable_collections",
                "code": code,
            },
        )

        e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="set_setting",
            kwargs={"key": "threshold", "value": 7},
        )
        e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="enqueue",
            kwargs={"value": 1},
        )
        e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="enqueue",
            kwargs={"value": 2},
        )
        e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="replace_first",
            kwargs={"value": 9},
        )

        settings = e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="get_settings",
            kwargs={},
        )
        queue = e.execute(
            sender="stu",
            contract_name="con_variable_collections",
            function_name="get_queue",
            kwargs={},
        )

        self.assertEqual(settings["result"], {"threshold": 7})
        self.assertEqual(queue["result"], [9, 2])

    def test_orm_hash_sets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_hash_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_hash_contract_path),
            auto_commit=True,
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "key1", "v": 1234},
            auto_commit=True,
        )
        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "another_key", "v": 9999},
            auto_commit=True,
        )

        key1 = self.d.get("con_orm_hash_contract.h:key1")
        another_key = self.d.get("con_orm_hash_contract.h:another_key")

        self.assertEqual(key1, 1234)
        self.assertEqual(another_key, 9999)

    def test_orm_hash_gets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_hash_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_hash_contract_path),
        )

        res = e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="get_h",
            kwargs={"k": "test"},
        )

        self.assertEqual(res["result"], None)

    def test_orm_hash_gets_and_sets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_hash_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_hash_contract_path),
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "key1", "v": 1234},
        )
        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "another_key", "v": 9999},
        )

        key1 = e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="get_h",
            kwargs={"k": "key1"},
        )
        another_key = e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="get_h",
            kwargs={"k": "another_key"},
        )

        self.assertEqual(key1["result"], 1234)
        self.assertEqual(another_key["result"], 9999)

    def test_orm_foreign_variable_sets_in_contract_doesnt_work(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )
        test_orm_foreign_key_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_foreign_key_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_variable_contract_path),
        )
        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_foreign_key_contract_path),
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="set_v",
            kwargs={"i": 1000},
        )

        # this should fail
        status = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_key_contract",
            function_name="set_fv",
            kwargs={"i": 999},
        )

        self.assertEqual(status["status_code"], 1)

        i = e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="get_v",
            kwargs={},
        )
        self.assertEqual(i["result"], 1000)

    def test_orm_foreign_variable_gets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_variable_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_variable_contract.s.py",
        )
        test_orm_foreign_key_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_foreign_key_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_variable_contract_path),
        )
        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_foreign_key_contract_path),
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_variable_contract",
            function_name="set_v",
            kwargs={"i": 424242},
        )
        # this should fail
        i = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_key_contract",
            function_name="get_fv",
            kwargs={},
        )

        self.assertEqual(i["result"], 424242)

    def test_orm_foreign_hash_sets_in_contract_doesnt_work(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_hash_contract.s.py",
        )
        test_orm_foreign_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_foreign_hash_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_hash_contract_path),
            auto_commit=True,
        )
        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_foreign_hash_contract_path),
            auto_commit=True,
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "key1", "v": 1234},
            auto_commit=True,
        )
        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "another_key", "v": 9999},
            auto_commit=True,
        )

        status_1 = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_hash_contract",
            function_name="set_fh",
            kwargs={"k": "key1", "v": 5555},
            auto_commit=True,
        )
        status_2 = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_hash_contract",
            function_name="set_fh",
            kwargs={"k": "another_key", "v": 1000},
            auto_commit=True,
        )

        key1 = self.d.get("con_orm_hash_contract.h:key1")
        another_key = self.d.get("con_orm_hash_contract.h:another_key")

        self.assertEqual(key1, 1234)
        self.assertEqual(another_key, 9999)
        self.assertEqual(status_1["status_code"], 1)
        self.assertEqual(status_2["status_code"], 1)

    def test_orm_foreign_hash_gets_and_sets_in_contract(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_hash_contract.s.py",
        )
        test_orm_foreign_hash_contract_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_foreign_hash_contract.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_hash_contract_path),
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_foreign_hash_contract_path),
        )

        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "key1", "v": 1234},
        )
        e.execute(
            sender="stu",
            contract_name="con_orm_hash_contract",
            function_name="set_h",
            kwargs={"k": "another_key", "v": 9999},
        )

        key1 = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_hash_contract",
            function_name="get_fh",
            kwargs={"k": "key1"},
        )
        another_key = e.execute(
            sender="stu",
            contract_name="con_orm_foreign_hash_contract",
            function_name="get_fh",
            kwargs={"k": "another_key"},
        )

        self.assertEqual(key1["result"], 1234)
        self.assertEqual(another_key["result"], 9999)

    def test_orm_contract_not_accessible(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_orm_no_contract_access_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "orm_no_contract_access.s.py",
        )

        output = e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_orm_no_contract_access_path),
        )
        self.assertEqual(output["status_code"], 1)
        self.assertIn(
            "Name '__Contract' must not start or end with underscore",
            str(output["result"]),
        )

    def test_construct_function_sets_properly(self):
        e = NativeExecutor(driver=self.d, metering=False)

        test_construct_function_works_path = os.path.join(
            os.path.dirname(__file__),
            "test_contracts",
            "construct_function_works.s.py",
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(test_construct_function_works_path),
        )

        output = e.execute(
            sender="stu",
            contract_name="con_construct_function_works",
            function_name="get",
            kwargs={},
        )

        self.assertEqual(output["result"], 42)

    def test_import_exported_function_works(self):
        e = NativeExecutor(driver=self.d, metering=False)

        import_this_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "import_this.s.py"
        )
        importing_that_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "importing_that.s.py"
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(import_this_path),
        )

        e.execute(
            **SUBMIT_CONTRACT,
            kwargs=submission_kwargs_for_file(importing_that_path),
        )

        output = e.execute(
            sender="stu", contract_name="con_importing_that", function_name="test", kwargs={}
        )
        self.assertEqual(output["result"], 12345 - 1000)

    def test_explicit_transaction_context_is_available_to_the_native_vm(self):
        from xian_runtime_types.time import Datetime

        source = "@export\ndef inspect():\n    return [now, ctx.caller]\n"
        self.client.submit(source, name="con_context")
        now = Datetime(2026, 11, 11)
        output = self.client.executor.execute(
            sender="alice",
            contract_name="con_context",
            function_name="inspect",
            kwargs={},
            environment={"now": now},
        )
        self.assertEqual(output["status_code"], 0, output["result"])
        self.assertEqual(output["result"], [now, "alice"])

    def test_arbitrary_environment_does_not_create_native_contract_globals(self):
        source = "@export\ndef inspect():\n    return host_secret\n"
        self.client.submit(source, name="con_context")
        output = self.client.executor.execute(
            sender="alice",
            contract_name="con_context",
            function_name="inspect",
            kwargs={},
            environment={"host_secret": 555},
        )
        self.assertEqual(output["status_code"], 1)
        self.assertIn("unknown name", str(output["result"]))
        self.assertEqual(output["writes"], {})


@pytest.mark.parametrize("initial, index", [([1, 2], 0), ({"old": 7}, "new")])
def test_native_variable_subscript_assignment_fails_without_persisting_partial_writes(
    tmp_path, initial, index
):
    source = "value = Variable()\n@export\ndef probe():\n"
    source += f"    value.set({initial!r})\n    value[{index!r}] = 99\n    return value.get()\n"
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_storage_subscript")
        output = client.get_contract_proxy("con_storage_subscript").probe(return_full_output=True)
        assert output["status_code"] == 1
        assert "subscript assignment is not supported" in str(output["result"])
        assert output["writes"] == {}
        assert output["events"] == []
        assert client.raw_driver.get_var("con_storage_subscript", "value") is None
