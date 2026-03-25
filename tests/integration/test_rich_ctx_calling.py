from unittest import TestCase
from contracting.client import ContractingClient


def con_module1():
    @export
    def get_context2():
        return {
            'name': 'get_context2',
            'owner': ctx.owner,
            'this': ctx.this,
            'signer': ctx.signer,
            'caller': ctx.caller,
            'entry': ctx.entry,
            'submission_name': ctx.submission_name
        }


def con_all_in_one():
    @export
    def call_me():
        return call_me_again()

    @export
    def call_me_again():
        return call_me_again_again()

    @export
    def call_me_again_again():
        return({
            'name': 'call_me_again_again',
            'owner': ctx.owner,
            'this': ctx.this,
            'signer': ctx.signer,
            'caller': ctx.caller,
            'entry': ctx.entry,
            'submission_name': ctx.submission_name
        })


def con_dynamic_import():

    @export
    def called_from_a_far():
        m = importlib.import_module('con_all_in_one')
        res = m.call_me_again_again()

        return [res, {
            'name': 'called_from_a_far',
            'owner': ctx.owner,
            'this': ctx.this,
            'signer': ctx.signer,
            'caller': ctx.caller,
            'entry': ctx.entry,
            'submission_name': ctx.submission_name
        }]

    @export
    def con_called_from_a_far_stacked():
        m = importlib.import_module('con_all_in_one')
        return m.call()

def con_submission_name_test():
    submission_name = Variable()

    @construct
    def seed():
        submission_name.set(ctx.submission_name)

    @export
    def get_submission_context():
        return submission_name.get()

    @export
    def get_entry_context():
        con_name, func_name = ctx.entry

        return {
            'entry_contract': con_name,
            'entry_function': func_name
        }



class TestRandomsContract(TestCase):
    def setUp(self):
        self.c = ContractingClient(signer='stu')
        self.c.flush()

        # Submit contracts
        self.c.submit(con_module1)
        self.c.submit(con_all_in_one)
        self.c.submit(con_dynamic_import)
        self.c.submit(con_submission_name_test)

    def tearDown(self):
        self.c.flush()

    def test_ctx2(self):
        module = self.c.get_contract('con_module1')
        res = module.get_context2()
        expected = {
            'name': 'get_context2',
            'entry': ('con_module1', 'get_context2'),
            'owner': None,
            'this': 'con_module1',
            'signer': 'stu',
            'caller': 'stu',
            'submission_name': None
        }
        self.assertDictEqual(res, expected)

    def test_multi_call_doesnt_affect_parameters(self):
        aio = self.c.get_contract('con_all_in_one')
        res = aio.call_me()

        expected = {
            'name': 'call_me_again_again',
            'entry': ('con_all_in_one', 'call_me'),
            'owner': None,
            'this': 'con_all_in_one',
            'signer': 'stu',
            'caller': 'stu',
            'submission_name': None
        }

        self.assertDictEqual(res, expected)

    def test_dynamic_call(self):
        dy = self.c.get_contract('con_dynamic_import')
        res1, res2 = dy.called_from_a_far()

        expected1 = {
            'name': 'call_me_again_again',
            'entry': ('con_dynamic_import', 'called_from_a_far'),
            'owner': None,
            'this': 'con_all_in_one',
            'signer': 'stu',
            'caller': 'con_dynamic_import',
            'submission_name': None
        }

        expected2 = {
            'name': 'called_from_a_far',
            'entry': ('con_dynamic_import', 'called_from_a_far'),
            'owner': None,
            'this': 'con_dynamic_import',
            'signer': 'stu',
            'caller': 'stu',
            'submission_name': None
        }

        self.assertDictEqual(res1, expected1)
        self.assertDictEqual(res2, expected2)

    def test_three_contract_call_chain_restores_each_frame(self):
        con_root = '''
@export
def call_mid():
    m = importlib.import_module('con_mid')
    leaf_ctx, mid_ctx = m.call_leaf()
    return {
        'root_ctx': {
            'this': ctx.this,
            'caller': ctx.caller,
            'signer': ctx.signer,
            'entry': ctx.entry,
        },
        'mid_ctx': mid_ctx,
        'leaf_ctx': leaf_ctx,
    }
'''
        con_mid = '''
@export
def call_leaf():
    m = importlib.import_module('con_leaf')
    leaf_ctx = m.inspect()
    return [
        leaf_ctx,
        {
            'this': ctx.this,
            'caller': ctx.caller,
            'signer': ctx.signer,
            'entry': ctx.entry,
        },
    ]
'''
        con_leaf = '''
@export
def inspect():
    return {
        'this': ctx.this,
        'caller': ctx.caller,
        'signer': ctx.signer,
        'entry': ctx.entry,
    }
'''

        self.c.submit(con_root, name='con_root')
        self.c.submit(con_mid, name='con_mid')
        self.c.submit(con_leaf, name='con_leaf')

        root = self.c.get_contract('con_root')
        result = root.call_mid()

        self.assertDictEqual(
            result['root_ctx'],
            {
                'this': 'con_root',
                'caller': 'stu',
                'signer': 'stu',
                'entry': ('con_root', 'call_mid'),
            },
        )
        self.assertDictEqual(
            result['mid_ctx'],
            {
                'this': 'con_mid',
                'caller': 'con_root',
                'signer': 'stu',
                'entry': ('con_root', 'call_mid'),
            },
        )
        self.assertDictEqual(
            result['leaf_ctx'],
            {
                'this': 'con_leaf',
                'caller': 'con_mid',
                'signer': 'stu',
                'entry': ('con_root', 'call_mid'),
            },
        )

    def test_reentering_original_contract_rewrites_and_restores_caller(self):
        con_root = '''
@export
def bounce():
    m = importlib.import_module('con_mid_reentry')
    return m.reenter_root()

@export
def inspect():
    return {
        'this': ctx.this,
        'caller': ctx.caller,
        'signer': ctx.signer,
        'entry': ctx.entry,
    }
'''
        con_mid = '''
@export
def reenter_root():
    root = importlib.import_module('con_root_reentry')
    reentered = root.inspect()
    return {
        'mid_ctx': {
            'this': ctx.this,
            'caller': ctx.caller,
            'signer': ctx.signer,
            'entry': ctx.entry,
        },
        'reentered_root_ctx': reentered,
    }
'''

        self.c.submit(con_root, name='con_root_reentry')
        self.c.submit(con_mid, name='con_mid_reentry')

        root = self.c.get_contract('con_root_reentry')
        result = root.bounce()

        self.assertDictEqual(
            result['mid_ctx'],
            {
                'this': 'con_mid_reentry',
                'caller': 'con_root_reentry',
                'signer': 'stu',
                'entry': ('con_root_reentry', 'bounce'),
            },
        )
        self.assertDictEqual(
            result['reentered_root_ctx'],
            {
                'this': 'con_root_reentry',
                'caller': 'con_mid_reentry',
                'signer': 'stu',
                'entry': ('con_root_reentry', 'bounce'),
            },
        )

    def test_submission_name_in_construct_function(self):
        contract = self.c.get_contract('con_submission_name_test')
        submission_name = contract.get_submission_context()

        self.assertEqual("con_submission_name_test", submission_name)

    def test_entry_context(self):
        contract = self.c.get_contract('con_submission_name_test')
        details = contract.get_entry_context()

        self.assertEqual("con_submission_name_test", details.get('entry_contract'))
        self.assertEqual("get_entry_context", details.get('entry_function'))

    def test_factory_deployment_sets_child_context_and_provenance(self):
        factory_code = '''
import submission

@export
def deploy_child(name: str, owner: str):
    code = """
module_ctx = Hash()
construct_ctx = Hash()

module_ctx['this'] = ctx.this
module_ctx['caller'] = ctx.caller
module_ctx['signer'] = ctx.signer
module_ctx['owner'] = ctx.owner
module_ctx['entry_contract'] = ctx.entry[0]
module_ctx['entry_function'] = ctx.entry[1]
module_ctx['submission_name'] = ctx.submission_name

@construct
def seed():
    construct_ctx['this'] = ctx.this
    construct_ctx['caller'] = ctx.caller
    construct_ctx['signer'] = ctx.signer
    construct_ctx['owner'] = ctx.owner
    construct_ctx['entry_contract'] = ctx.entry[0]
    construct_ctx['entry_function'] = ctx.entry[1]
    construct_ctx['submission_name'] = ctx.submission_name

@export
def ready():
    return True
"""

    submission.submit_contract(name=name, code=code, owner=owner)
'''

        self.c.submit(factory_code, name='con_factory')

        output = self.c.executor.execute(
            sender='stu',
            contract_name='con_factory',
            function_name='deploy_child',
            kwargs={'name': 'con_factory_child', 'owner': 'carol'},
            auto_commit=True,
        )

        self.assertEqual(output['status_code'], 0)
        self.assertTrue(
            any(
                event['event'] == 'ContractDeployed'
                and event['data_indexed']['name'] == 'con_factory_child'
                and event['caller'] == 'con_factory'
                and event['signer'] == 'stu'
                for event in output['events']
            )
        )

        self.assertEqual(
            self.c.get_var('con_factory_child', '__developer__'),
            'con_factory',
        )
        self.assertEqual(
            self.c.get_var('con_factory_child', '__deployer__'),
            'con_factory',
        )
        self.assertEqual(
            self.c.get_var('con_factory_child', '__initiator__'),
            'stu',
        )
        self.assertEqual(
            self.c.get_var('con_factory_child', '__owner__'),
            'carol',
        )

        expected_ctx = {
            'this': 'con_factory_child',
            'caller': 'con_factory',
            'signer': 'stu',
            'owner': 'carol',
            'entry_contract': 'con_factory',
            'entry_function': 'deploy_child',
            'submission_name': 'con_factory_child',
        }
        for key, value in expected_ctx.items():
            self.assertEqual(
                self.c.get_var('con_factory_child', 'module_ctx', [key]),
                value,
            )
            self.assertEqual(
                self.c.get_var('con_factory_child', 'construct_ctx', [key]),
                value,
            )
