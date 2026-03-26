@export
def available():
    return zk.is_available()


@export
def verify(vk_hex: str, proof_hex: str, public_inputs: list):
    return zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs)
