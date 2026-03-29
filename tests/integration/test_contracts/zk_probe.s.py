@export
def available():
    return zk.is_available()


@export
def verify(vk_hex: str, proof_hex: str, public_inputs: list):
    return zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs)


@export
def has_vk(vk_id: str):
    return zk.has_verifying_key(vk_id)


@export
def verify_registered(vk_id: str, proof_hex: str, public_inputs: list):
    return zk.verify_groth16(vk_id, proof_hex, public_inputs)
