@export
def verify_range(commitment: str, bit_commitments: list, bit_proofs: list, link_proof: list, bits: int):
    return crypto.range_proof_verify(commitment, bit_commitments, bit_proofs, link_proof, bits)
