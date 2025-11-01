from unittest import TestCase
import os

from contracting.storage.driver import Driver
from contracting.execution.executor import Executor

from tests.unit.test_crypto import make_range_proof


SUBMISSION_CALL_KWARGS = {
    'sender': 'stu',
    'contract_name': 'submission',
    'function_name': 'submit_contract',
}


def submission_payload_for(path: str):
    base = os.path.basename(path)
    name, *_ = base.split('.')
    with open(path) as f:
        code = f.read()
    return {
        'name': f'con_{name}',
        'code': code,
    }


class TestCryptoContractSubmission(TestCase):
    def setUp(self):
        self.driver = Driver()
        self.driver.flush_full()

        submission_path = os.path.join(
            os.path.dirname(__file__), 'test_contracts', 'submission.s.py'
        )
        with open(submission_path) as f:
            submission_code = f.read()
        self.driver.set_contract(name='submission', code=submission_code)
        self.driver.commit()

    def tearDown(self):
        self.driver.flush_full()

    def test_verify_range_accepts_valid_proof(self):
        executor = Executor(metering=False)

        contract_path = os.path.join(
            os.path.dirname(__file__), 'test_contracts', 'crypto_usage.s.py'
        )
        executor.execute(
            **SUBMISSION_CALL_KWARGS,
            kwargs=submission_payload_for(contract_path),
        )

        commitment, bit_commitments, bit_proofs, link_proof = make_range_proof(173, bits=8)

        payload = {
            'commitment': commitment,
            'bit_commitments': list(bit_commitments),
            'bit_proofs': [list(proof) for proof in bit_proofs],
            'link_proof': list(link_proof),
            'bits': 8,
        }

        result = executor.execute('stu', 'con_crypto_usage', 'verify_range', kwargs=payload)

        self.assertTrue(result['result'])
