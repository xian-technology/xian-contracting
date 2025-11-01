@export
def verify_range(commitment: str, bit_commitments: list, bit_proofs: list, link_proof: list, bits: int):
    # Normalise the iterable inputs so clients can submit JSON-friendly lists.
    canonical_bit_proofs = [tuple(proof) for proof in bit_proofs]
    canonical_link_proof = tuple(link_proof)
    return crypto.range_proof_verify(commitment, bit_commitments, canonical_bit_proofs, canonical_link_proof, bits)
