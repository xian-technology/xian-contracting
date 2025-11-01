from unittest import TestCase
from contracting.execution import runtime
from contracting.stdlib import env
from contracting.stdlib.bridge import crypto as C
import copy

from tests.unit.test_crypto import (
    make_range_proof,
    make_same_value_proof,
    pedersen_commit_for_tests,
)


class TestCryptoContractMetering(TestCase):
    def setUp(self):
        scope = env.gather()
        scope['__contract__'] = True

        contract_source = """
def pedersen_add(a, b):
    return crypto.pedersen_add(a, b)

def pedersen_sub(a, b):
    return crypto.pedersen_sub(a, b)

def pedersen_neg(value):
    return crypto.pedersen_neg(value)

def pedersen_eq(a, b):
    return crypto.pedersen_eq(a, b)

def verify_range(commitment, bit_commitments, bit_proofs, link_proof, bits):
    return crypto.range_proof_verify(commitment, bit_commitments, bit_proofs, tuple(link_proof), bits)

def same_value(commitment_a, commitment_b, proof):
    return crypto.pedersen_same_value_proof_verify(commitment_a, commitment_b, proof)
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

    def test_pedersen_group_ops_are_deterministic_under_metering(self):
        pedersen_add = self.scope['pedersen_add']
        pedersen_sub = self.scope['pedersen_sub']
        pedersen_neg = self.scope['pedersen_neg']
        pedersen_eq = self.scope['pedersen_eq']
        same_value = self.scope['same_value']

        v1 = "1337"
        v2 = "4242"
        r1 = "11" * 32
        r2 = "22" * 32

        c1 = pedersen_commit_for_tests(v1, r1)
        c2 = pedersen_commit_for_tests(v2, r2)

        expected_sum = C.pedersen_add(c1, c2)
        expected_diff = C.pedersen_sub(c1, c2)
        expected_neg = C.pedersen_neg(c1)

        add_result, add_stamps = self._run_metered(pedersen_add, c1, c2)
        add_again, add_stamps_again = self._run_metered(pedersen_add, c1, c2)
        self.assertEqual(add_result, expected_sum)
        self.assertEqual(add_again, expected_sum)
        self.assertGreater(add_stamps, 0)
        self.assertEqual(add_stamps, add_stamps_again)

        sub_result, sub_stamps = self._run_metered(pedersen_sub, c1, c2)
        sub_again, sub_stamps_again = self._run_metered(pedersen_sub, c1, c2)
        self.assertEqual(sub_result, expected_diff)
        self.assertEqual(sub_again, expected_diff)
        self.assertGreater(sub_stamps, 0)
        self.assertEqual(sub_stamps, sub_stamps_again)

        neg_result, neg_stamps = self._run_metered(pedersen_neg, c1)
        neg_again, neg_stamps_again = self._run_metered(pedersen_neg, c1)
        self.assertEqual(neg_result, expected_neg)
        self.assertEqual(neg_again, expected_neg)
        self.assertGreater(neg_stamps, 0)
        self.assertEqual(neg_stamps, neg_stamps_again)

        eq_result, eq_stamps = self._run_metered(pedersen_eq, c1, expected_sum)
        eq_again, eq_stamps_again = self._run_metered(pedersen_eq, c1, expected_sum)
        self.assertFalse(eq_result)
        self.assertFalse(eq_again)
        self.assertGreater(eq_stamps, 0)
        self.assertEqual(eq_stamps, eq_stamps_again)

        eq_true, eq_true_stamps = self._run_metered(pedersen_eq, c1, c1)
        eq_true_again, eq_true_stamps_again = self._run_metered(pedersen_eq, c1, c1)
        self.assertTrue(eq_true)
        self.assertTrue(eq_true_again)
        self.assertGreater(eq_true_stamps, 0)
        self.assertEqual(eq_true_stamps, eq_true_stamps_again)

        C_same_a, C_same_b, proof = make_same_value_proof(99)
        sv_result, sv_stamps = self._run_metered(same_value, C_same_a, C_same_b, proof)
        sv_again, sv_stamps_again = self._run_metered(same_value, C_same_a, C_same_b, proof)
        self.assertTrue(sv_result)
        self.assertTrue(sv_again)
        self.assertGreater(sv_stamps, 0)
        self.assertEqual(sv_stamps, sv_stamps_again)

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
