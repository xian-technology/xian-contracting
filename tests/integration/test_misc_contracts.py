import importlib
from unittest import TestCase
from xian_runtime_types.time import Datetime
from contracting.client import ContractingClient
from contracting.storage.driver import Driver
import os


def too_many_writes():
    v = Variable()

    @export
    def single():
        v.set("a" * (128 * 1024 + 1))

    @export
    def multiple():
        for i in range(32 * 1024 + 1):
            v.set("a")

    @export
    def not_enough():
        v.set("a" * (30 * 1024))

    @export
    def run():
        a = ""
        for i in range(1000000):
            a += "NAME" * 10

        return a

    @export
    def run2():
        a = 0
        b = ""
        for i in range(1000000):
            b = b + "wow" + "baseName" * a
            a += 1
        return b


def exploit():
    @construct
    def seed():
        a = 0
        b = ""
        for i in range(10000000):
            b = b + "wow" + "baseName" * a
            a += 1
        return b

    @export
    def b():
        pass


class TestMiscContracts(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

        submission = self.c.get_contract("submission")

        self.c.submit(too_many_writes, name="con_too_many_writes")

        # submit erc20 clone
        thing_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "thing.s.py"
        )

        with open(thing_path) as f:
            code = f.read()
            self.c.submit(code, name="con_thing")

        foreign_thing_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "foreign_thing.s.py"
        )

        with open(foreign_thing_path) as f:
            code = f.read()
            self.c.submit(code, name="con_foreign_thing")

        self.thing = self.c.get_contract("con_thing")
        self.foreign_thing = self.c.get_contract("con_foreign_thing")

    def tearDown(self):
        self.c.raw_driver.flush_full()

    def test_H_values_return(self):
        output = self.foreign_thing.read_H_hello()
        self.assertEqual(output, "there")

        output = self.foreign_thing.read_H_something()
        self.assertEqual(output, "else")

    def test_cant_modify_H(self):
        with self.assertRaises(ReferenceError):
            self.foreign_thing.set_H(k="hello", v="not_there")

    def test_cant_add_H(self):
        with self.assertRaises(ReferenceError):
            self.foreign_thing.set_H(k="asdf", v="123")

    def test_cant_set_V(self):
        with self.assertRaises(ReferenceError):
            self.foreign_thing.set_V(v=123)

    def test_V_returns(self):
        output = self.foreign_thing.read_V()
        self.assertEqual(output, "hi")

    def test_hash_clone_from_foreign_hash_snapshots_values(self):
        self.c.submit(con_clone_source, name="con_clone_source")
        self.c.submit(con_clone_target, name="con_clone_target")

        cloned = self.c.get_contract("con_clone_target")
        source = self.c.get_contract("con_clone_source")

        self.assertEqual(cloned.read(key="alice"), 100)
        self.assertEqual(cloned.read(key="settings"), {"limit": 7})

        cloned.mutate_limit(limit=99)

        self.assertEqual(cloned.read(key="settings"), {"limit": 99})
        self.assertEqual(source.read(key="settings"), {"limit": 7})

    def test_single_too_many_writes_fails(self):
        tmwc = self.c.get_contract("con_too_many_writes")
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        self.assertEqual(
            self.c.executor.execute(
                contract_name="con_too_many_writes",
                function_name="single",
                kwargs={},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.metering = False

    def test_multiple_too_many_writes_fails(self):
        tmwc = self.c.get_contract("con_too_many_writes")
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        # AssertEquals that the status code is 1 (failed tx)
        self.assertEqual(
            self.c.executor.execute(
                contract_name="con_too_many_writes",
                function_name="multiple",
                kwargs={},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.metering = False

    def test_failed_once_doesnt_affect_others(self):
        tmwc = self.c.get_contract("con_too_many_writes")
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        # AssertEquals that the status code is 1 (failed tx)
        self.assertEqual(
            self.c.executor.execute(
                contract_name="con_too_many_writes",
                function_name="multiple",
                kwargs={},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.execute(
            contract_name="con_too_many_writes",
            function_name="not_enough",
            kwargs={},
            chi=1000,
            sender="stu",
        )
        self.c.executor.metering = False

    def test_memory_overload(self):
        tmwc = self.c.get_contract("con_too_many_writes")
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        # AssertEquals that the status code is 1 (failed tx)
        self.assertEqual(
            self.c.executor.execute(
                contract_name="con_too_many_writes",
                function_name="run",
                kwargs={},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.metering = False

    def test_memory_overload2(self):
        tmwc = self.c.get_contract("con_too_many_writes")
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        # AssertEquals that the status code is 1 (failed tx)
        self.assertEqual(
            self.c.executor.execute(
                contract_name="con_too_many_writes",
                function_name="run2",
                kwargs={},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.metering = False

    def test_memory_exploit(self):
        self.c.executor.metering = True
        self.c.set_var(
            contract="currency",
            variable="balances",
            arguments=["stu"],
            value=1000000,
        )
        # AssertEquals that the status code is 1 (failed tx)
        self.assertEqual(
            self.c.executor.execute(
                contract_name="submission",
                function_name="submit_contract",
                kwargs={"name": "exploit", "code": exploit},
                chi=1000,
                sender="stu",
            )["status_code"],
            1,
        )
        self.c.executor.metering = False


class TestPassHash(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

        submission = self.c.get_contract("submission")

        # submit erc20 clone
        pass_hash_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "pass_hash.s.py"
        )

        with open(pass_hash_path) as f:
            code = f.read()
            self.c.submit(code, name="con_pass_hash")

        test_pass_hash_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "con_pass_hash.s.py"
        )

        with open(test_pass_hash_path) as f:
            code = f.read()
            self.c.submit(code, name="con_test_pass_hash")

        self.pass_hash = self.c.get_contract("con_pass_hash")
        self.test_pass_hash = self.c.get_contract("con_test_pass_hash")

    def test_store_value(self):
        self.test_pass_hash.store(k="thing", v="value")
        output = self.test_pass_hash.get(k="thing")

        self.assertEqual(output, "value")


def some_test_contract():
    @export
    def return_something():
        return 1


def import_submission():
    import submission

    @export
    def haha():
        code = """
factory_caller = Variable()

@construct
def seed():
    factory_caller.set(ctx.caller)

@export
def get_factory_caller():
    return factory_caller.get()
"""
        submission.submit_contract(name="con_something123", code=code)


def bad_submission_factory():
    import submission

    @export
    def deploy_bad():
        code = """
@construct
def seed():
    assert False, "boom"
"""
        submission.submit_contract(name="con_bad_child", code=code)


def malicious_owner_rewrite():
    @export
    def attack(contract: str, new_owner: str):
        Contract.set_owner(contract, new_owner)


def malicious_developer_rewrite():
    @export
    def attack(contract: str, new_developer: str):
        Contract.set_developer(contract, new_developer)


class TestDeveloperSubmission(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

    def test_submit_sets_developer(self):
        self.c.submit(some_test_contract, name="con_some_test_contract")

        dev = self.c.get_var("con_some_test_contract", "__developer__")
        deployer = self.c.get_var("con_some_test_contract", "__deployer__")
        initiator = self.c.get_var("con_some_test_contract", "__initiator__")

        self.assertEqual(dev, "stu")
        self.assertEqual(deployer, "stu")
        self.assertEqual(initiator, "stu")

    def test_change_developer_if_developer_works(self):
        self.c.submit(some_test_contract, name="con_some_test_contract")

        submission = self.c.get_contract("submission")

        submission.change_developer(
            contract="con_some_test_contract", new_developer="not_stu"
        )

        dev = self.c.get_var("con_some_test_contract", "__developer__")

        self.assertEqual(dev, "not_stu")

    def test_change_developer_prevents_new_change(self):
        self.c.submit(some_test_contract, name="con_some_test_contract")

        submission = self.c.get_contract("submission")

        submission.change_developer(
            contract="con_some_test_contract", new_developer="not_stu"
        )

        with self.assertRaises(AssertionError):
            submission.change_developer(
                contract="con_some_test_contract", new_developer="woohoo"
            )

    def test_change_owner_updates_runtime_owner(self):
        self.c.submit(
            some_test_contract,
            name="con_owned_contract",
            owner="stu",
        )

        submission = self.c.get_contract("submission")
        submission.change_owner(
            contract="con_owned_contract",
            new_owner="not_stu",
        )

        self.assertEqual(
            self.c.get_var("con_owned_contract", "__owner__"),
            "not_stu",
        )

    def test_change_owner_changes_runtime_access(self):
        self.c.submit(
            some_test_contract,
            name="con_owned_contract",
            owner="stu",
        )

        submission = self.c.get_contract("submission")
        target = self.c.get_contract("con_owned_contract")
        submission.change_owner(
            contract="con_owned_contract",
            new_owner="not_stu",
        )

        with self.assertRaises(Exception):
            target.return_something()

        self.assertEqual(
            target.return_something(signer="not_stu"),
            1,
        )

    def test_change_owner_requires_current_owner(self):
        self.c.submit(
            some_test_contract,
            name="con_owned_contract",
            owner="stu",
        )

        submission = self.c.get_contract("submission")

        with self.assertRaises(AssertionError):
            submission.change_owner(
                contract="con_owned_contract",
                new_owner="not_stu",
                signer="raghu",
            )

    def test_change_owner_rejects_contract_without_runtime_owner(self):
        self.c.submit(some_test_contract, name="con_unowned_contract")

        submission = self.c.get_contract("submission")

        with self.assertRaises(AssertionError):
            submission.change_owner(
                contract="con_unowned_contract",
                new_owner="not_stu",
            )

    def test_change_owner_emits_event(self):
        self.c.submit(
            some_test_contract,
            name="con_owned_contract",
            owner="stu",
        )

        output = self.c.executor.execute(
            sender="stu",
            contract_name="submission",
            function_name="change_owner",
            kwargs={
                "contract": "con_owned_contract",
                "new_owner": "not_stu",
            },
            auto_commit=True,
        )

        self.assertEqual(output["status_code"], 0)
        self.assertTrue(
            any(
                event["event"] == "ContractOwnerChanged"
                and event["data_indexed"]["contract"] == "con_owned_contract"
                and event["data_indexed"]["new_owner"] == "not_stu"
                and event["data"]["previous_owner"] == "stu"
                and event["caller"] == "stu"
                for event in output["events"]
            )
        )

    def test_contract_cannot_rewrite_other_contract_owner(self):
        self.c.submit(
            some_test_contract,
            name="con_owned_contract",
            owner="stu",
        )
        self.c.submit(malicious_owner_rewrite, name="con_owner_attacker")

        attacker = self.c.get_contract("con_owner_attacker")

        with self.assertRaises(AssertionError):
            attacker.attack(contract="con_owned_contract", new_owner="mallory")

        self.assertEqual(
            self.c.get_var("con_owned_contract", "__owner__"),
            "stu",
        )

    def test_contract_cannot_rewrite_other_contract_developer(self):
        self.c.submit(some_test_contract, name="con_some_test_contract")
        self.c.submit(malicious_developer_rewrite, name="con_developer_attacker")

        attacker = self.c.get_contract("con_developer_attacker")

        with self.assertRaises(AssertionError):
            attacker.attack(
                contract="con_some_test_contract",
                new_developer="mallory",
            )

        self.assertEqual(
            self.c.get_var("con_some_test_contract", "__developer__"),
            "stu",
        )

    def test_can_import_submission_for_factory_deploy(self):
        self.c.submit(import_submission, name="con_import_submission")

        imp_con = self.c.get_contract("con_import_submission")
        imp_con.haha()

        self.assertEqual(
            self.c.get_var("con_something123", "factory_caller"),
            "con_import_submission",
        )
        self.assertEqual(
            self.c.get_var("con_something123", "__developer__"),
            "con_import_submission",
        )
        self.assertEqual(
            self.c.get_var("con_something123", "__deployer__"),
            "con_import_submission",
        )
        self.assertEqual(
            self.c.get_var("con_something123", "__initiator__"),
            "stu",
        )

    def test_factory_deploy_rolls_back_on_child_constructor_failure(self):
        self.c.submit(bad_submission_factory, name="con_bad_submission_factory")

        output = self.c.executor.execute(
            sender="stu",
            contract_name="con_bad_submission_factory",
            function_name="deploy_bad",
            kwargs={},
            auto_commit=True,
        )

        self.assertEqual(output["status_code"], 1)
        self.assertIsNone(self.c.raw_driver.get_contract("con_bad_child"))
        self.assertIsNone(
            self.c.raw_driver.get_contract_source("con_bad_child")
        )
        self.assertIsNone(self.c.get_var("con_bad_child", "__deployer__"))
        self.assertIsNone(self.c.get_var("con_bad_child", "__initiator__"))


def con_float_thing():
    @export
    def float_thing_fn(
        currency_reserve: float, token_reserve: float, currency_amount: float
    ):
        k = currency_reserve * token_reserve

        new_currency_reserve = currency_reserve + currency_amount
        new_token_reserve = k / new_currency_reserve

        tokens_purchased = token_reserve - new_token_reserve
        return tokens_purchased


class TestFloatThing(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

    def test_can_add(self):
        self.c.submit(con_float_thing, name="con_float_thing")

        ft_con = self.c.get_contract("con_float_thing")
        ft_con.float_thing_fn(
            currency_reserve=50000.125,
            token_reserve=52.45,
            currency_amount=100.25,
        )


def a():
    @export
    def x():
        return 1


def module_hack():
    v = Variable()

    @export
    def hack():
        hack.__module__
        return 1


def class_var():
    @export
    def hack():
        v = Variable
        x = v(contract="currency", name="balances")


def class_hash():
    @export
    def hack():
        v = Hash
        x = v(contract="currency", name="balances")


def exec_contract():
    @export
    def fn():
        def builtins__():
            pass

    wExec = builtins__["exec"]
    wExec("print('hello world')")


def type_exploit():
    @export
    def attack(to: str):
        # before
        # assert amount > 0, 'Cannot send negative balances!'
        def gt(a, b):
            print("gt", a, b)
            return True

        # assert balances[sender] >= amount, 'Not enough coins to send!'
        def le(a, b):
            print("lt", a, b)
            return True

        # balances[sender] -= amount
        def rsub(a, b):
            print("rsub", a, b)
            return b

        # balances[to] += amount
        def radd(a, b):
            print("radd", a, b)
            return 100

        wAmount = type(
            "wAmount",
            (),
            {"__gt__": gt, "__le__": le, "__radd__": radd, "__rsub__": rsub},
        )
        fake_amount_object = wAmount()


def con_test_one():
    h = Hash()

    @construct
    def seed():
        h["a"] = 100
        h["b"] = 999

    @export
    def output():
        return h["a"], h["b"]


def con_test_two():
    f = ForeignHash(foreign_contract="con_test_one", foreign_name="h")

    @export
    def clear():
        f.clear()


def con_clone_source():
    h = Hash()

    @construct
    def seed():
        h["alice"] = 100
        h["settings"] = {"limit": 7}

    @export
    def read(key: str):
        return h[key]


def con_clone_target():
    source = ForeignHash(
        foreign_contract="con_clone_source",
        foreign_name="h",
    )
    snapshot = Hash()

    @construct
    def seed():
        snapshot["stale"] = 999
        snapshot.clone_from(source)

    @export
    def read(key: str):
        return snapshot[key]

    @export
    def mutate_limit(limit: int):
        settings = snapshot["settings"]
        settings["limit"] = limit
        snapshot["settings"] = settings


def test_closure():
    def export(contract):
        def decorator(func):
            def enter(*args, **kwargs):
                result = func(*args, **kwargs)
                return result

            return enter

        return decorator

    @export
    def closure_inner():
        return 1


def test_closure2():
    def export(contract):
        a = 1

        def decorator(func):
            b = 2

            def enter(*args, **kwargs):
                result = func(*args, **kwargs)
                return result

            return enter

        return decorator

    @export
    def closure_inner():
        return 1


class TestHackThing(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu")
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

    def test_can_add(self):
        self.c.submit(a, name="con_a")
        with self.assertRaises(Exception):
            self.c.submit(module_hack, name="con_module_hack")

            ft_con = self.c.get_contract("con_module_hack")

            ft_con.hack()

    def test_cant_submit_class_var(self):
        with self.assertRaises(Exception):
            self.c.submit(class_var)

    def test_cant_submit_class_hash(self):
        with self.assertRaises(Exception):
            self.c.submit(class_hash)

    def test_cant_submit_exec(self):
        with self.assertRaises(Exception):
            self.c.submit(exec_contract)

    def test_cant_submit_type(self):
        with self.assertRaises(Exception):
            self.c.submit(type_exploit)

    def test_cant_clear_foreign_hash(self):
        self.c.submit(con_test_one)
        self.c.submit(con_test_two)

        t2 = self.c.get_contract("con_test_two")

        with self.assertRaises(Exception):
            t2.clear()

    def test_no_closures(self):
        with self.assertRaises(Exception):
            self.c.submit(test_closure)

    def test_no_closures_work_around(self):
        with self.assertRaises(Exception):
            self.c.submit(test_closure2)


def con_test_fixed():
    v = Variable()

    @construct
    def seed():
        v.set([1.234, 5.678])

    @export
    def multiply():
        a, b = v.get()
        return a * b


class TestFixed(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer="stu", driver=Driver())
        self.c.raw_driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), "test_contracts", "submission.s.py"
        )

        with open(submission_path) as f:
            contract = f.read()

        self.c.raw_driver.set_contract(
            name="submission",
            code=contract,
        )

        self.c.raw_driver.commit()

    def test_can_multiply(self):
        self.c.submit(con_test_fixed)

        self.c.raw_driver.commit()
        self.c.raw_driver.flush_cache()
        f = self.c.get_contract("con_test_fixed")

        z = f.multiply()
        self.assertEqual(z, 1.234 * 5.678)


if __name__ == "__main__":
    import unittest

    unittest.main()
