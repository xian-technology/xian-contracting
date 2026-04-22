from unittest import TestCase
from contracting import constants
from contracting.execution.runtime import rt
from contracting.storage.driver import Driver
from contracting.storage.orm import (
    Datum,
    ForeignHash,
    ForeignVariable,
    Hash,
    LogEvent,
    Variable,
    indexed,
)
from xian_runtime_types.decimal import ContractingDecimal

# from contracting.stdlib.env import gather

# Variable = gather()['Variable']
# Hash = gather()['Hash']
# ForeignVariable = gather()['ForeignVariable']
# ForeignHash = gather()['ForeignHash']

driver = Driver()


class TestDatum(TestCase):
    def setUp(self):
        driver.flush_full()

    def tearDown(self):
        driver.flush_full()

    def test_init(self):
        d = Datum("stustu", "test", driver)
        self.assertEqual(d._key, driver.make_key("stustu", "test"))


class TestVariable(TestCase):
    def setUp(self):
        driver.flush_full()

    def tearDown(self):
        # _driver.flush_full()
        pass

    def test_set(self):
        contract = "stustu"
        name = "balance"
        delimiter = constants.INDEX_SEPARATOR

        raw_key = "{}{}{}".format(contract, delimiter, name)

        v = Variable(contract, name, driver=driver)
        v.set(1000)

        self.assertEqual(driver.get(raw_key), 1000)

    def test_get(self):
        contract = "stustu"
        name = "balance"
        delimiter = constants.INDEX_SEPARATOR

        raw_key = "{}{}{}".format(contract, delimiter, name)
        driver.set(raw_key, 1234)

        v = Variable(contract, name, driver=driver)
        _v = v.get()

        self.assertEqual(_v, 1234)

    def test_set_get(self):
        contract = "stustu"
        name = "balance"

        v = Variable(contract, name, driver=driver)
        v.set(1000)

        _v = v.get()

        self.assertEqual(_v, 1000)

    def test_default_value(self):
        contract = "stustu"
        name = "balance"

        v = Variable(contract, name, driver=driver, default_value=999)
        self.assertEqual(v.get(), 999)

        v.set(123)
        self.assertEqual(v.get(), 123)

        v.set(None)
        self.assertEqual(v.get(), 999)

    def test_mutable_default_is_copied(self):
        contract = "stustu"
        name = "cfg"
        v = Variable(contract, name, driver=driver, default_value={"a": []})
        first = v.get()
        first["a"].append(1)
        second = v.get()
        self.assertEqual(second, {"a": []})

    def test_stored_mutable_value_is_copied_on_get(self):
        contract = "stustu"
        name = "cfg"
        raw_key = driver.make_key(contract, name)
        driver.set(raw_key, {"a": []})

        v = Variable(contract, name, driver=driver)
        first = v.get()
        first["a"].append(1)

        self.assertEqual(v.get(), {"a": []})

    def test_setitem_persists_dict_mutation(self):
        v = Variable("stustu", "cfg", driver=driver, default_value={})

        v["mode"] = "strict"

        self.assertEqual(v.get(), {"mode": "strict"})

    def test_delitem_persists_dict_mutation(self):
        v = Variable(
            "stustu", "cfg", driver=driver, default_value={"mode": "strict"}
        )

        del v["mode"]

        self.assertEqual(v.get(), {})

    def test_update_persists_dict_mutation(self):
        v = Variable(
            "stustu", "cfg", driver=driver, default_value={"mode": "strict"}
        )

        v.update({"retry": 3})

        self.assertEqual(v.get(), {"mode": "strict", "retry": 3})

    def test_append_and_index_assignment_persist_list_mutation(self):
        v = Variable("stustu", "queue", driver=driver, default_value=[])

        v.append(1)
        v.append(2)
        v[0] = 9

        self.assertEqual(v.get(), [9, 2])

    def test_pop_persists_list_mutation_and_returns_value(self):
        v = Variable("stustu", "queue", driver=driver, default_value=[1, 2, 3])

        value = v.pop()

        self.assertEqual(value, 3)
        self.assertEqual(v.get(), [1, 2])

    def test_clear_persists_collection_mutation(self):
        dict_var = Variable(
            "stustu", "cfg", driver=driver, default_value={"mode": "strict"}
        )
        list_var = Variable(
            "stustu", "queue", driver=driver, default_value=[1, 2]
        )

        dict_var.clear()
        list_var.clear()

        self.assertEqual(dict_var.get(), {})
        self.assertEqual(list_var.get(), [])

    def test_list_helpers_require_list_values(self):
        v = Variable("stustu", "value", driver=driver, default_value=123)

        with self.assertRaises(AssertionError):
            v.append(1)

    def test_dict_helpers_require_dict_values(self):
        v = Variable("stustu", "value", driver=driver, default_value=123)

        with self.assertRaises(AssertionError):
            v.update({"mode": "strict"})


class TestHash(TestCase):
    def setUp(self):
        driver.flush_full()

    def tearDown(self):
        driver.flush_full()

    def test_set(self):
        contract = "stustu"
        name = "balance"
        delimiter = constants.INDEX_SEPARATOR

        raw_key_1 = "{}{}{}".format(contract, delimiter, name)
        raw_key_1 += ":stu"

        h = Hash(contract, name, driver=driver)

        h._set("stu", 1234)

        driver.commit()

        self.assertEqual(driver.get(raw_key_1), 1234)

    def test_get(self):
        contract = "stustu"
        name = "balance"
        delimiter = constants.INDEX_SEPARATOR

        raw_key_1 = "{}{}{}".format(contract, delimiter, name)
        raw_key_1 += ":stu"

        driver.set(raw_key_1, 1234)

        h = Hash(contract, name, driver=driver)

        self.assertEqual(h._get("stu"), 1234)

    def test_set_get(self):
        contract = "stustu"
        name = "balance"

        h = Hash(contract, name, driver=driver)

        h._set("stu", 1234)
        _h = h._get("stu")

        self.assertEqual(_h, 1234)

        h._set("colin", 5678)
        _h2 = h._get("colin")

        self.assertEqual(_h2, 5678)

    def test_setitem(self):
        contract = "blah"
        name = "scoob"
        delimiter = constants.INDEX_SEPARATOR

        h = Hash(contract, name, driver=driver)

        prefix = "{}{}{}{}".format(contract, delimiter, name, h._delimiter)

        h["stu"] = 9999999

        raw_key = "{}stu".format(prefix)

        self.assertEqual(driver.get(raw_key), 9999999)

    def test_getitem(self):
        contract = "blah"
        name = "scoob"
        delimiter = constants.INDEX_SEPARATOR

        h = Hash(contract, name, driver=driver)

        prefix = "{}{}{}{}".format(contract, delimiter, name, h._delimiter)

        raw_key = "{}stu".format(prefix)

        driver.set(raw_key, 54321)

        self.assertEqual(h["stu"], 54321)

    def test_setitems(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)
        h["stu"] = 123
        h["stu", "raghu"] = 1000
        driver.commit()

        val = driver.get("blah.scoob:stu:raghu")
        self.assertEqual(val, 1000)

    def test_setitem_delimiter_illegal(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)
        with self.assertRaises(AssertionError):
            h["stu:123"] = 123

    def test_setitems_too_many_dimensions_fails(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        with self.assertRaises(Exception):
            h[
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
            ] = 1000

    def test_setitems_key_too_large(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        key = "a" * 1025

        with self.assertRaises(Exception):
            h[key] = 100

    def test_setitem_value_too_large(self):
        pass

    def test_setitems_keys_too_large(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        key1 = "a" * 800
        key2 = "b" * 100
        key3 = "c" * 200

        with self.assertRaises(Exception):
            h[key1, key2, key3] = 100

    def test_getitems_keys(self):
        contract = "blah"
        name = "scoob"
        delimiter = constants.INDEX_SEPARATOR

        h = Hash(contract, name, driver=driver)

        prefix = "{}{}{}{}".format(contract, delimiter, name, h._delimiter)

        raw_key = "{}stu:raghu".format(prefix)

        driver.set(raw_key, 54321)

        driver.commit()

        self.assertEqual(h["stu", "raghu"], 54321)

    def test_getsetitems(self):
        contract = "blah"
        name = "scoob"
        delimiter = constants.INDEX_SEPARATOR

        h = Hash(contract, name, driver=driver)

        h["stu", "raghu"] = 999

        driver.commit()

        self.assertEqual(h["stu", "raghu"], 999)

    def test_getitems_keys_too_large(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        key1 = "a" * 800
        key2 = "b" * 100
        key3 = "c" * 200

        with self.assertRaises(Exception):
            x = h[key1, key2, key3]

    def test_getitems_too_many_dimensions_fails(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        with self.assertRaises(Exception):
            a = h[
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
                "a",
                "b",
                "c",
            ]

    def test_getitems_key_too_large(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver)

        key = "a" * 1025

        with self.assertRaises(Exception):
            a = h[key]

    def test_getitem_returns_default_value_if_none(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver, default_value=0)

        self.assertEqual(h["hello"], 0)

    def test_get_all_when_none_exist(self):
        contract = "blah"
        name = "scoob"

        h = Hash(contract, name, driver=driver, default_value=0)
        all = h.all()
        self.assertEqual(all, [])

    def test_get_all_after_setting(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh["1"] = 123
        hsh["2"] = 456
        hsh["3"] = 789

        l = [123, 456, 789]

        # TODO - this ok ? :D
        # driver.commit()

        # we care about whats included, not order
        self.assertSetEqual(set(hsh.all()), set(l))

    def test_get_all_returns_defensive_copies_for_mutable_values(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value={})
        hsh["1"] = {"count": 1}

        values = hsh.all()
        values[0]["count"] = 99

        self.assertEqual(hsh["1"], {"count": 1})

    def test_items_returns_kv_pairs(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh["1"] = 123
        hsh["2"] = 456
        hsh["3"] = 789

        # driver.commit()

        kvs = {"blah.scoob:3": 789, "blah.scoob:1": 123, "blah.scoob:2": 456}

        got = hsh._items()

        self.assertDictEqual(kvs, got)

    def test_items_returns_defensive_copies_for_mutable_values(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value={})
        hsh["1"] = {"count": 1}

        items = hsh._items()
        items["blah.scoob:1"]["count"] = 77

        self.assertEqual(hsh["1"], {"count": 1})

    def test_items_multi_hash_returns_kv_pairs(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[0, "1"] = 123
        hsh[0, "2"] = 456
        hsh[0, "3"] = 789

        hsh[1, "1"] = 999
        hsh[1, "2"] = 888
        hsh[1, "3"] = 777

        # driver.commit()

        kvs = {
            "blah.scoob:0:3": 789,
            "blah.scoob:0:1": 123,
            "blah.scoob:0:2": 456,
        }

        got = hsh._items(0)

        self.assertDictEqual(kvs, got)

    def test_items_multi_hash_returns_all(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[0, "1"] = 123
        hsh[0, "2"] = 456
        hsh[0, "3"] = 789

        hsh[1, "1"] = 999
        hsh[1, "2"] = 888
        hsh[1, "3"] = 777

        # driver.commit()

        kvs = {
            "blah.scoob:0:3": 789,
            "blah.scoob:0:1": 123,
            "blah.scoob:0:2": 456,
            "blah.scoob:1:3": 777,
            "blah.scoob:1:1": 999,
            "blah.scoob:1:2": 888,
        }

        got = hsh._items()

        self.assertDictEqual(kvs, got)

    def test_items_clear_deletes_only_multi_hash(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[0, "1"] = 123
        hsh[0, "2"] = 456
        hsh[0, "3"] = 789

        hsh[1, "1"] = 999
        hsh[1, "2"] = 888
        hsh[1, "3"] = 777

        # driver.commit()

        kvs = {
            "blah.scoob:0:3": 789,
            "blah.scoob:0:1": 123,
            "blah.scoob:0:2": 456,
        }

        hsh.clear(1)

        # driver.commit()

        got = hsh._items()

        self.assertDictEqual(kvs, got)

    def test_all_multihash_returns_values(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[0, "1"] = 123
        hsh[0, "2"] = 456
        hsh[0, "3"] = 789

        hsh[1, "1"] = 999
        hsh[1, "2"] = 888
        hsh[1, "3"] = 777

        l = [123, 456, 789]

        # TODO
        # Test works when below line is commented out - not sure if our driver works differently now
        # driver.commit()

        # we care about whats included, not order
        self.assertSetEqual(set(hsh.all(0)), set(l))

    def test_multihash_multiple_dims_clear_behaves_similar_to_single_dim(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[1, 0, "1"] = 123
        hsh[1, 0, "2"] = 456
        hsh[1, 0, "3"] = 789

        hsh[1, 1, "1"] = 999
        hsh[1, 1, "2"] = 888
        hsh[1, 1, "3"] = 777

        # driver.commit()

        kvs = {
            "blah.scoob:1:0:3": 789,
            "blah.scoob:1:0:1": 123,
            "blah.scoob:1:0:2": 456,
        }

        hsh.clear(1, 1)

        # driver.commit()

        got = hsh._items()

        self.assertDictEqual(kvs, got)

    def test_multihash_multiple_dims_all_gets_items_similar_to_single_dim(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh[1, 0, "1"] = 123
        hsh[1, 0, "2"] = 456
        hsh[1, 0, "3"] = 789

        hsh[1, 1, "1"] = 999
        hsh[1, 1, "2"] = 888
        hsh[1, 1, "3"] = 777

        l = [123, 456, 789]

        # driver.commit()

        # we care about whats included, not order
        self.assertSetEqual(set(hsh.all(1, 0)), set(l))

    def test_clear_items_deletes_all_key_value_pairs(self):
        contract = "blah"
        name = "scoob"

        hsh = Hash(contract, name, driver=driver, default_value=0)

        hsh["1"] = 123
        hsh["2"] = 456
        hsh["3"] = 789

        # TODO - test works without commit - is ok
        # driver.commit()

        kvs = {"blah.scoob:3": 789, "blah.scoob:1": 123, "blah.scoob:2": 456}

        got = hsh._items()

        self.assertDictEqual(kvs, got)
        hsh.clear()

        # driver.commit()

        got = hsh._items()

        self.assertDictEqual({}, got)

    def test_clone_from_hash_replaces_existing_contents(self):
        source = Hash("source", "balances", driver=driver, default_value=0)
        target = Hash("target", "balances", driver=driver, default_value=0)

        source["alice"] = 100
        source["bob"] = 200
        target["stale"] = 999

        target.clone_from(source)

        self.assertEqual(target["alice"], 100)
        self.assertEqual(target["bob"], 200)
        self.assertEqual(target._items(), {
            "target.balances:alice": 100,
            "target.balances:bob": 200,
        })

    def test_clone_from_hash_copies_mutable_values(self):
        source = Hash("source", "settings", driver=driver, default_value={})
        target = Hash("target", "settings", driver=driver, default_value={})

        source["limits"] = {"daily": 7}

        target.clone_from(source)

        cloned = target["limits"]
        cloned["daily"] = 99
        target["limits"] = cloned

        self.assertEqual(source["limits"], {"daily": 7})
        self.assertEqual(target["limits"], {"daily": 99})


class TestForeignVariable(TestCase):
    def setUp(self):
        driver.flush_full()

    def tearDown(self):
        driver.flush_full()

    def test_set(self):
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignVariable(contract, name, f_contract, f_name, driver=driver)

        with self.assertRaises(ReferenceError):
            f.set("poo")

    def test_get(self):
        # set up the foreign variable
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignVariable(contract, name, f_contract, f_name, driver=driver)

        # set the variable using the foreign names (assuming this is another contract namespace)
        v = Variable(f_contract, f_name, driver=driver)
        v.set("howdy")

        self.assertEqual(f.get(), "howdy")


class TestForeignHash(TestCase):
    def setUp(self):
        driver.flush_full()

    def tearDown(self):
        # _driver.flush_full()
        pass

    def test_set(self):
        # set up the foreign variable
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignHash(contract, name, f_contract, f_name, driver=driver)

        with self.assertRaises(ReferenceError):
            f._set("stu", 1234)

    def test_get(self):
        # set up the foreign variable
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignHash(contract, name, f_contract, f_name, driver=driver)

        h = Hash(f_contract, f_name, driver=driver)
        h._set("howdy", 555)

        self.assertEqual(f._get("howdy"), 555)

    def test_setitem(self):
        # set up the foreign variable
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignHash(contract, name, f_contract, f_name, driver=driver)

        with self.assertRaises(ReferenceError):
            f["stu"] = 1234

    def test_getitem(self):
        # set up the foreign variable
        contract = "stustu"
        name = "balance"

        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignHash(contract, name, f_contract, f_name, driver=driver)

        h = Hash(f_contract, f_name, driver=driver)
        h["howdy"] = 555

        self.assertEqual(f["howdy"], 555)

    def test_getitem_returns_copy_for_mutable_values(self):
        contract = "stustu"
        name = "balance"
        f_contract = "colinbucks"
        f_name = "balances"

        f = ForeignHash(contract, name, f_contract, f_name, driver=driver)

        h = Hash(f_contract, f_name, driver=driver)
        h["settings"] = {"limit": 7}

        value = f["settings"]
        value["limit"] = 99

        self.assertEqual(f["settings"], {"limit": 7})

    def test_clone_from_foreign_hash(self):
        source = Hash("colinbucks", "balances", driver=driver, default_value=0)
        source["howdy"] = 555
        source["there"] = 777

        foreign = ForeignHash(
            "stustu",
            "balance",
            "colinbucks",
            "balances",
            driver=driver,
        )
        target = Hash("stustu", "snapshot", driver=driver, default_value=0)
        target["stale"] = 123

        target.clone_from(foreign)

        self.assertEqual(target["howdy"], 555)
        self.assertEqual(target["there"], 777)
        self.assertEqual(target._items(), {
            "stustu.snapshot:howdy": 555,
            "stustu.snapshot:there": 777,
        })

    def test_clone_from_raises_for_foreign_hash_target(self):
        foreign = ForeignHash(
            "stustu",
            "balance",
            "colinbucks",
            "balances",
            driver=driver,
        )
        source = Hash("source", "balances", driver=driver, default_value=0)

        with self.assertRaises(ReferenceError):
            foreign.clone_from(source)


class TestLogEvent(TestCase):
    def setUp(self):
        driver.flush_full()
        self.base_state = rt.context._base_state.copy()
        rt.context._reset()
        rt.context._base_state = {
            "this": "test_contract",
            "caller": "caller_1",
            "owner": None,
            "signer": "signer_1",
            "entry": ("test_contract", "transfer"),
            "submission_name": None,
        }
        self.args = {
            "from": indexed(str),
            "to": indexed(str),
            "amount": (int, float),
        }
        self.log_event = LogEvent(
            "Transfer",
            self.args,
            contract="test_contract",
            name="transfer_event",
            driver=driver,
        )

    def tearDown(self):
        rt.context._reset()
        rt.context._base_state = self.base_state
        driver.flush_full()

    def test_log_event_accepts_clean_constructor(self):
        self.assertEqual(self.log_event._event, "Transfer")
        self.assertEqual(self.log_event._contract, "test_contract")
        self.assertEqual(self.log_event._name, "transfer_event")
        self.assertEqual(self.log_event._key, "test_contract.transfer_event")

    def test_log_event_rejects_legacy_constructor(self):
        with self.assertRaises(TypeError):
            LogEvent(
                "legacy_contract",
                "approve_event",
                event="Approve",
                params={"owner": str},
                driver=driver,
            )

        with self.assertRaises(TypeError):
            LogEvent(
                "legacy_contract",
                "approve_event",
                "Approve",
                {"owner": str},
                driver=driver,
            )

    def test_log_event_accepts_keyword_constructor(self):
        log_event = LogEvent(
            event="Approve",
            params={"owner": str},
            contract="token",
            name="approve_event",
            driver=driver,
        )

        self.assertEqual(log_event._contract, "token")
        self.assertEqual(log_event._name, "approve_event")
        self.assertEqual(log_event._event, "Approve")
        self.assertEqual(log_event._params["owner"]["type"], (str,))
        self.assertFalse(log_event._params["owner"]["idx"])

    def test_log_event_normalizes_shorthand_without_mutating_input(self):
        raw_args = {
            "owner": str,
            "spender": indexed(str),
            "amount": (int, float, ContractingDecimal),
        }

        log_event = LogEvent(
            "Approve",
            raw_args,
            contract="token",
            name="approve_event",
            driver=driver,
        )

        self.assertIs(raw_args["owner"], str)
        self.assertEqual(raw_args["spender"], {"type": str, "idx": True})
        self.assertEqual(log_event._params["owner"]["type"], (str,))
        self.assertFalse(log_event._params["owner"]["idx"])
        self.assertEqual(
            log_event._params["amount"]["type"],
            (int, float, ContractingDecimal),
        )

    def test_log_event_rejects_empty_event_names(self):
        with self.assertRaisesRegex(
            AssertionError, "Event name must not be empty."
        ):
            LogEvent(
                "",
                {"owner": str},
                contract="token",
                name="approve_event",
                driver=driver,
            )

    def test_log_event_with_max_indexed_args(self):
        log_event = LogEvent(
            "Transfer",
            {
                "from": indexed(str),
                "to": indexed(str),
                "amount": indexed(int, float),
            },
            contract="currency",
            name="transfer_event",
            driver=driver,
        )

        self.assertIsInstance(log_event, LogEvent)

    def test_log_event_with_too_many_indexed_args(self):
        with self.assertRaisesRegex(
            AssertionError, "Args must have at most three indexed arguments."
        ):
            LogEvent(
                "Transfer",
                {
                    "from": indexed(str),
                    "to": indexed(str),
                    "amount": indexed(int, float),
                    "extra": indexed(str),
                },
                contract="currency",
                name="transfer_event",
                driver=driver,
            )

    def test_log_event_rejects_malformed_schema(self):
        with self.assertRaisesRegex(
            AssertionError, "Argument owner must declare a type."
        ):
            LogEvent(
                "Approve",
                {"owner": {"idx": True}},
                contract="token",
                name="approve_event",
                driver=driver,
            )

    def test_log_event_rejects_non_standard_types(self):
        with self.assertRaisesRegex(
            AssertionError,
            "Each type in args must be str, int, float, decimal or bool.",
        ):
            LogEvent(
                "Transfer",
                {"from": indexed(list)},
                contract="token",
                name="transfer_event",
                driver=driver,
            )

    def test_write_event_success_uses_emit_time_context(self):
        rt.context._base_state["caller"] = "caller_2"
        rt.context._base_state["signer"] = "signer_2"

        self.log_event.write_event(
            {
                "from": "Alice",
                "to": "Bob",
                "amount": 100,
            }
        )

        emitted = driver.log_events[-1]
        self.assertEqual(emitted["contract"], "test_contract")
        self.assertEqual(emitted["event"], "Transfer")
        self.assertEqual(emitted["signer"], "signer_2")
        self.assertEqual(emitted["caller"], "caller_2")
        self.assertEqual(emitted["data_indexed"], {"from": "Alice", "to": "Bob"})
        self.assertEqual(emitted["data"], {"amount": 100})

    def test_same_event_name_across_contracts_is_disambiguated_by_contract(self):
        first = LogEvent(
            "Transfer",
            {"from": str},
            contract="contract_a",
            name="transfer_a",
            driver=driver,
        )
        second = LogEvent(
            "Transfer",
            {"from": str},
            contract="contract_b",
            name="transfer_b",
            driver=driver,
        )

        first.write_event({"from": "Alice"})
        second.write_event({"from": "Bob"})

        self.assertEqual(driver.log_events[-2]["contract"], "contract_a")
        self.assertEqual(driver.log_events[-1]["contract"], "contract_b")
        self.assertEqual(driver.log_events[-2]["event"], "Transfer")
        self.assertEqual(driver.log_events[-1]["event"], "Transfer")

    def test_write_event_missing_argument(self):
        with self.assertRaisesRegex(
            AssertionError,
            "Data must have the same number of arguments as specified in the event.",
        ):
            self.log_event.write_event({"from": "Alice", "amount": 100})

    def test_write_event_rejects_non_dict_data(self):
        with self.assertRaisesRegex(
            AssertionError, "Event data must be a dictionary."
        ):
            self.log_event.write_event(None)

    def test_write_event_with_invalid_argument_names(self):
        with self.assertRaisesRegex(
            AssertionError,
            "Unexpected argument unexpected_arg in the data dictionary.",
        ):
            self.log_event.write_event(
                {
                    "from": "Alice",
                    "to": "Bob",
                    "unexpected_arg": 100,
                }
            )

    def test_write_event_wrong_type(self):
        with self.assertRaisesRegex(
            AssertionError, "Argument amount is the wrong type!"
        ):
            self.log_event.write_event(
                {
                    "from": "Alice",
                    "to": "Bob",
                    "amount": "one hundred",
                }
            )

    def test_write_event_rejects_large_values(self):
        with self.assertRaisesRegex(
            AssertionError, "Argument from is too large"
        ):
            self.log_event.write_event(
                {
                    "from": "A" * 2048,
                    "to": "Bob",
                    "amount": 100,
                }
            )
