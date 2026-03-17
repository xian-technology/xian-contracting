import os
from unittest import TestCase

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


def submission_kwargs_for_file(f):
    # Get the file name only by splitting off directories
    split = f.split('/')
    split = split[-1]

    # Now split off the .s
    split = split.split('.')
    contract_name = split[0]

    with open(f) as file:
        contract_code = file.read()

    return {
        'name': f'con_{contract_name}',
        'code': contract_code,
    }


TEST_SUBMISSION_KWARGS = {
    'sender': 'stu',
    'contract_name': 'submission',
    'function_name': 'submit_contract'
}


class TestMetering(TestCase):
    def setUp(self):
        # Hard load the submission contract
        self.d = Driver()
        self.d.flush_full()

        submission_path = os.path.join(os.path.dirname(__file__), "test_contracts", "submission.s.py")

        with open(submission_path) as f:
            contract = f.read()

        self.d.set_contract(name='submission',
                            code=contract)
        self.d.commit()

        currency_path = os.path.join(os.path.dirname(__file__), "test_contracts", "currency.s.py")
        # Execute the currency contract with metering disabled
        self.e = Executor(driver=self.d)
        self.e.execute(**TEST_SUBMISSION_KWARGS,
                       kwargs=submission_kwargs_for_file(currency_path), metering=False, auto_commit=True)

    def tearDown(self):
        self.d.flush_full()
   
