VkRegistered = LogEvent(
    event="VerifyingKeyRegistered",
    params={
        "vk_id": {"type": str, "idx": True},
        "scheme": {"type": str},
        "curve": {"type": str},
        "vk_hash": {"type": str, "idx": True},
        "active": {"type": bool},
    },
)

VkStatusChanged = LogEvent(
    event="VerifyingKeyStatusChanged",
    params={
        "vk_id": {"type": str, "idx": True},
        "active": {"type": bool},
    },
)

registry_owner = Variable()
verifying_keys = Hash()


def require_owner():
    owner = registry_owner.get()
    assert owner is not None, "Registry is not seeded!"
    assert ctx.caller == owner, "Only registry owner!"
    return owner


def require_vk_id(vk_id: str):
    assert isinstance(vk_id, str) and vk_id != "", "vk_id must be non-empty!"
    assert len(vk_id) <= 128, "vk_id is too long!"


def require_hex_blob(name: str, value: str):
    assert isinstance(value, str), name + " must be a string!"
    assert value.startswith("0x"), name + " must be 0x-prefixed!"
    assert len(value) > 2 and len(value) % 2 == 0, (
        name + " must contain whole bytes!"
    )
    int(value[2:], 16)


def seed_registry(owner: str = None):
    assert registry_owner.get() is None, "Registry already seeded!"
    if owner is None or owner == "":
        owner = ctx.caller
    assert isinstance(owner, str) and owner != "", (
        "Owner must be a non-empty string!"
    )
    registry_owner.set(owner)
    return owner


@construct
def init_registry(owner: str = None):
    return seed_registry(owner)


@export
def seed(owner: str = None):
    return seed_registry(owner)


@export
def owner():
    return registry_owner.get()


@export
def register_vk(
    vk_id: str,
    vk_hex: str,
    scheme: str = "groth16",
    curve: str = "bn254",
    circuit_name: str = "",
    version: str = "",
    active: bool = True,
):
    require_owner()
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is None, "vk_id already registered!"
    if scheme is None:
        scheme = "groth16"
    if curve is None:
        curve = "bn254"
    if circuit_name is None:
        circuit_name = ""
    if version is None:
        version = ""
    if active is None:
        active = True
    assert scheme == "groth16", "Only Groth16 is supported!"
    assert curve == "bn254", "Only BN254 is supported!"
    require_hex_blob("vk_hex", vk_hex)
    assert isinstance(circuit_name, str), "circuit_name must be a string!"
    assert isinstance(version, str), "version must be a string!"

    vk_hash = hashlib.sha3(vk_hex)
    verifying_keys[vk_id, "scheme"] = scheme
    verifying_keys[vk_id, "curve"] = curve
    verifying_keys[vk_id, "vk_hex"] = vk_hex
    verifying_keys[vk_id, "vk_hash"] = vk_hash
    verifying_keys[vk_id, "created_at"] = now
    verifying_keys[vk_id, "active"] = active
    verifying_keys[vk_id, "circuit_name"] = circuit_name
    verifying_keys[vk_id, "version"] = version

    VkRegistered(
        {
            "vk_id": vk_id,
            "scheme": scheme,
            "curve": curve,
            "vk_hash": vk_hash,
            "active": active,
        }
    )

    return {
        "vk_id": vk_id,
        "vk_hash": vk_hash,
        "active": active,
    }


@export
def set_active(vk_id: str, active: bool):
    require_owner()
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is not None, "Unknown vk_id!"
    verifying_keys[vk_id, "active"] = active
    VkStatusChanged({"vk_id": vk_id, "active": active})
    return active


@export
def get_vk_info(vk_id: str):
    require_vk_id(vk_id)
    vk_hex = verifying_keys[vk_id, "vk_hex"]
    if vk_hex is None:
        return None

    return {
        "vk_id": vk_id,
        "scheme": verifying_keys[vk_id, "scheme"],
        "curve": verifying_keys[vk_id, "curve"],
        "vk_hash": verifying_keys[vk_id, "vk_hash"],
        "active": verifying_keys[vk_id, "active"],
        "circuit_name": verifying_keys[vk_id, "circuit_name"],
        "version": verifying_keys[vk_id, "version"],
        "created_at": verifying_keys[vk_id, "created_at"],
    }
