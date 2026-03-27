from unittest import TestCase

from contracting.client import ContractingClient


ROOT_REENTRY_CONTRACT = """
counter = Variable(default_value=0)

RootEvent = LogEvent(
    event='RootEvent',
    params={'stage': {'type': str, 'idx': True}},
)

@export
def start():
    counter.set(1)
    RootEvent({'stage': 'root_start'})
    child = importlib.import_module('con_reentry_child')
    child.reenter_and_fail()

@export
def fail_after_reentry():
    counter.set(99)
    RootEvent({'stage': 'root_fail'})
    assert False, 'reentry failed'

@export
def get_counter():
    return counter.get()
"""


CHILD_REENTRY_CONTRACT = """
seen = Variable(default_value='')

ChildEvent = LogEvent(
    event='ChildEvent',
    params={'stage': {'type': str, 'idx': True}},
)

@export
def reenter_and_fail():
    seen.set('entered')
    ChildEvent({'stage': 'child_enter'})
    root = importlib.import_module('con_reentry_root')
    root.fail_after_reentry()

@export
def get_seen():
    return seen.get()
"""


DIRECT_TRANSIENT_GLOBAL_CONTRACT = """
counter = 0

@export
def bump():
    global counter
    counter += 1
    return counter
"""


DYNAMIC_TRANSIENT_CHILD_CONTRACT = """
counter = 0

@export
def bump():
    global counter
    counter += 1
    return counter
"""


DYNAMIC_TRANSIENT_PARENT_CONTRACT = """
@export
def bounce():
    child = importlib.import_module('con_transient_child')
    return child.bump()
"""


RELOAD_V1_CONTRACT = """
@export
def version():
    return 'v1'
"""


RELOAD_V2_CONTRACT = """
@export
def version():
    return 'v2'
"""


HASH_ALL_MUTATION_CONTRACT = """
records = Hash(default_value={})

@export
def mutate_via_all():
    records['alpha'] = {'count': 1}
    values = records.all()
    values[0]['count'] = 99
    return records['alpha']
"""


class TestRuntimeSecurity(TestCase):
    def setUp(self):
        self.client = ContractingClient(signer="stu")
        self.client.flush()
        self.client.submit(ROOT_REENTRY_CONTRACT, name="con_reentry_root")
        self.client.submit(CHILD_REENTRY_CONTRACT, name="con_reentry_child")

    def tearDown(self):
        self.client.flush()

    def test_reentrant_failure_rolls_back_all_nested_writes_and_events(self):
        output = self.client.executor.execute(
            sender="stu",
            contract_name="con_reentry_root",
            function_name="start",
            kwargs={},
            metering=False,
        )

        self.assertEqual(output["status_code"], 1)
        self.assertEqual(str(output["result"]), "reentry failed")
        self.assertEqual(output["writes"], {})
        self.assertEqual(output["events"], [])
        self.assertIsNone(self.client.raw_driver.get("con_reentry_root.counter"))
        self.assertIsNone(self.client.raw_driver.get("con_reentry_child.seen"))

        root = self.client.get_contract("con_reentry_root")
        child = self.client.get_contract("con_reentry_child")
        self.assertEqual(root.get_counter(), 0)
        self.assertEqual(child.get_seen(), "")

    def test_contract_python_globals_do_not_persist_across_transactions(self):
        self.client.submit(
            DIRECT_TRANSIENT_GLOBAL_CONTRACT,
            name="con_transient_direct",
        )

        contract = self.client.get_contract("con_transient_direct")

        self.assertEqual(contract.bump(), 1)
        self.assertEqual(contract.bump(), 1)

    def test_dynamic_imported_contract_globals_do_not_persist(self):
        self.client.submit(
            DYNAMIC_TRANSIENT_CHILD_CONTRACT,
            name="con_transient_child",
        )
        self.client.submit(
            DYNAMIC_TRANSIENT_PARENT_CONTRACT,
            name="con_transient_parent",
        )

        parent = self.client.get_contract("con_transient_parent")

        self.assertEqual(parent.bounce(), 1)
        self.assertEqual(parent.bounce(), 1)

    def test_redeploy_after_flush_uses_fresh_contract_code(self):
        self.client.raw_driver.set_contract_from_source(
            name="con_reload_probe",
            source=RELOAD_V1_CONTRACT,
        )
        self.client.raw_driver.commit()

        probe = self.client.get_contract("con_reload_probe")
        self.assertEqual(probe.version(), "v1")

        self.client.raw_driver.flush_full()
        self.client.set_submission_contract()
        self.client.raw_driver.set_contract_from_source(
            name="con_reload_probe",
            source=RELOAD_V2_CONTRACT,
        )
        self.client.raw_driver.commit()

        probe = self.client.get_contract("con_reload_probe")
        self.assertEqual(probe.version(), "v2")

    def test_hash_prefix_reads_do_not_expose_live_mutable_state(self):
        self.client.submit(
            HASH_ALL_MUTATION_CONTRACT,
            name="con_hash_all_mutation",
        )

        contract = self.client.get_contract("con_hash_all_mutation")

        self.assertEqual(contract.mutate_via_all(), {"count": 1})
