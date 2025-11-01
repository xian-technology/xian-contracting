from unittest import TestCase
from contracting.execution import runtime
from contracting.stdlib import env
from contracting.stdlib.bridge import crypto as C
import copy

from tests.unit.test_crypto import make_range_proof


class TestCryptoContractMetering(TestCase):
    def setUp(self):
        scope = env.gather()
        scope['__contract__'] = True

        contract_source = """
def commit(value, blinding):
    return crypto.pedersen_commit(str(value), blinding)

def verify_range(commitment, bit_commitments, bit_proofs, link_proof, bits):
    return crypto.range_proof_verify(commitment, bit_commitments, bit_proofs, tuple(link_proof), bits)
"""
        exec(contract_source, scope)
        self.scope = scope

    def tearDown(self):
        runtime.rt.clean_up()

    def _run_metered(self, func, *args, **kwargs):
        func.__globals__['__contract__'] = True
        runtime.rt.set_up(stmps=1_000_000, meter=True)
        try:
            result = func(*args, **kwargs)
            stamps = runtime.rt.tracer.get_stamp_used()
            return result, stamps
        finally:
            runtime.rt.clean_up()

    def test_pedersen_commit_is_deterministic_under_metering(self):
        commit = self.scope['commit']

        value = 1337
        blinding = "11" * 32
        expected = C.pedersen_commit(str(value), blinding)

        first_result, first_stamps = self._run_metered(commit, value, blinding)
        second_result, second_stamps = self._run_metered(commit, value, blinding)

        self.assertEqual(first_result, expected)
        self.assertEqual(second_result, expected)
        self.assertEqual(first_result, second_result)
        self.assertGreater(first_stamps, 0)
        self.assertEqual(first_stamps, second_stamps)

    def test_range_proof_verify_metering_is_stable(self):
        verify_range = self.scope['verify_range']

        bits = 8
        value = 173
        C_amt_hex, bit_cmts, bit_proofs, link_pf = make_range_proof(value, bits=bits)
        self.assertTrue(C.range_proof_verify(C_amt_hex, bit_cmts, bit_proofs, link_pf, bits))

        args = (
            C_amt_hex,
            list(bit_cmts),
            copy.deepcopy(bit_proofs),
            list(link_pf),
            bits,
        )

        first_result, first_stamps = self._run_metered(verify_range, *args)
        second_result, second_stamps = self._run_metered(verify_range, *args)

        self.assertTrue(first_result)
        self.assertTrue(second_result)
        self.assertGreater(first_stamps, 0)
        self.assertEqual(first_stamps, second_stamps)
