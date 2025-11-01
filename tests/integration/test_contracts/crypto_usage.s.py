@export
def commit(value: int, blinding: str):
    # Mirror the stdlib bridge usage within a contract context.
    return crypto.pedersen_commit(str(value), blinding)


@export
def verify_range(commitment: str, bit_commitments: list, bit_proofs: list, link_proof: list, bits: int):
    # Accept either tuple or list for link proof and forward to the bridge module.
    return crypto.range_proof_verify(commitment, bit_commitments, bit_proofs, tuple(link_proof), bits)
