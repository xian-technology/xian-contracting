import os
from unittest import TestCase

import contracting

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


def submission_kwargs_for_file(path):
    with open(path) as file:
        code = file.read()
    name = os.path.basename(path).split('.')[0]
    return {
        'name': f'con_{name}',
        'code': code,
    }


class TestFailedCrossContractRevert(TestCase):
    def setUp(self):
        self.driver = Driver()
        self.driver.flush_full()

        with open(contracting.__path__[0] + '/contracts/submission.s.py') as f:
            contract = f.read()

        self.driver.set_contract(name='submission', code=contract)
        self.driver.commit()

        self.executor = Executor(metering=False)

        contracts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_contracts')
        self.market_path = os.path.join(contracts_dir, 'otc_failure.s.py')

        self.executor.execute(
            sender='stu',
            contract_name='submission',
            function_name='submit_contract',
            kwargs=submission_kwargs_for_file(self.market_path),
            auto_commit=True,
        )

    def tearDown(self):
        self.executor.bypass_privates = False
        self.driver.flush_full()

    def test_reverts_all_state_on_failed_cross_contract_call(self):
        result = self.executor.execute('bob', 'con_otc_failure', 'take', kwargs={})

        self.assertEqual(result['status_code'], 1)
        self.assertIsInstance(result['result'], AssertionError)
        self.assertIn('Not enough coins to send.', result['result'].args[0])
        self.assertNotIn(
            'con_otc_failure.otc_listing:listing',
            self.executor.driver.pending_reads,
            'Failed transaction should not leave mutated entries cached in pending_reads.',
        )

        listing = self.executor.execute('bob', 'con_otc_failure', 'get_listing', kwargs={})
        self.assertEqual(listing['result']['status'], 'OPEN')

        guard_state = self.executor.execute('bob', 'con_otc_failure', 'guard_active', kwargs={})
        self.assertFalse(guard_state['result'])

        second_attempt = self.executor.execute('bob', 'con_otc_failure', 'take', kwargs={})
        self.assertEqual(second_attempt['status_code'], 1)
        self.assertIsInstance(second_attempt['result'], AssertionError)
        self.assertIn('Not enough coins to send.', second_attempt['result'].args[0])
