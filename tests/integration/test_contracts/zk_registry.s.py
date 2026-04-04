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

VkLifecycleChanged = LogEvent(
    event="VerifyingKeyLifecycleChanged",
    params={
        "vk_id": {"type": str, "idx": True},
        "deprecated": {"type": bool},
        "replacement_vk_id": {"type": str},
    },
)

registry_owner = Variable()
verifying_keys = Hash()
vk_count = Variable()
vk_index = Hash()
vk_ids = Hash()


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


def normalize_text(value):
    if value is None:
        return ""
    assert isinstance(value, str), "metadata value must be a string!"
    return value


def normalize_count(name: str, value):
    if value is None:
        return 0
    assert isinstance(value, int), name + " must be an integer!"
    assert value >= 0, name + " must be non-negative!"
    return value


def require_optional_vk_id(vk_id: str):
    if vk_id is None or vk_id == "":
        return ""
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is not None, "Unknown replacement vk_id!"
    return vk_id


def seed_registry(owner: str = None):
    assert registry_owner.get() is None, "Registry already seeded!"
    if owner is None or owner == "":
        owner = ctx.caller
    assert isinstance(owner, str) and owner != "", (
        "Owner must be a non-empty string!"
    )
    registry_owner.set(owner)
    vk_count.set(0)
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
    circuit_family: str = "",
    statement_version: str = "",
    artifact_contract_name: str = "",
    tree_depth: int = None,
    leaf_capacity: int = None,
    max_inputs: int = None,
    max_outputs: int = None,
    setup_mode: str = "",
    setup_ceremony: str = "",
    artifact_hash: str = "",
    bundle_hash: str = "",
    warning: str = "",
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
    circuit_name = normalize_text(circuit_name)
    version = normalize_text(version)
    circuit_family = normalize_text(circuit_family)
    statement_version = normalize_text(statement_version)
    artifact_contract_name = normalize_text(artifact_contract_name)
    setup_mode = normalize_text(setup_mode)
    setup_ceremony = normalize_text(setup_ceremony)
    warning = normalize_text(warning)
    tree_depth = normalize_count("tree_depth", tree_depth)
    leaf_capacity = normalize_count("leaf_capacity", leaf_capacity)
    max_inputs = normalize_count("max_inputs", max_inputs)
    max_outputs = normalize_count("max_outputs", max_outputs)
    artifact_hash = normalize_text(artifact_hash)
    bundle_hash = normalize_text(bundle_hash)
    if artifact_hash != "":
        require_hex_blob("artifact_hash", artifact_hash)
    if bundle_hash != "":
        require_hex_blob("bundle_hash", bundle_hash)

    vk_hash = hashlib.sha3(vk_hex)
    index = vk_count.get()
    verifying_keys[vk_id, "scheme"] = scheme
    verifying_keys[vk_id, "curve"] = curve
    verifying_keys[vk_id, "vk_hex"] = vk_hex
    verifying_keys[vk_id, "vk_hash"] = vk_hash
    verifying_keys[vk_id, "created_at"] = now
    verifying_keys[vk_id, "active"] = active
    verifying_keys[vk_id, "circuit_name"] = circuit_name
    verifying_keys[vk_id, "version"] = version
    verifying_keys[vk_id, "circuit_family"] = circuit_family
    verifying_keys[vk_id, "statement_version"] = statement_version
    verifying_keys[vk_id, "contract_name"] = artifact_contract_name
    verifying_keys[vk_id, "artifact_contract_name"] = artifact_contract_name
    verifying_keys[vk_id, "tree_depth"] = tree_depth
    verifying_keys[vk_id, "leaf_capacity"] = leaf_capacity
    verifying_keys[vk_id, "max_inputs"] = max_inputs
    verifying_keys[vk_id, "max_outputs"] = max_outputs
    verifying_keys[vk_id, "setup_mode"] = setup_mode
    verifying_keys[vk_id, "setup_ceremony"] = setup_ceremony
    verifying_keys[vk_id, "artifact_hash"] = artifact_hash
    verifying_keys[vk_id, "bundle_hash"] = bundle_hash
    verifying_keys[vk_id, "warning"] = warning
    verifying_keys[vk_id, "deprecated"] = False
    verifying_keys[vk_id, "deprecated_at"] = None
    verifying_keys[vk_id, "replacement_vk_id"] = ""
    verifying_keys[vk_id, "index"] = index
    vk_index[vk_id] = index
    vk_ids[index] = vk_id
    vk_count.set(index + 1)

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
        "index": index,
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
def deprecate_vk(vk_id: str, replacement_vk_id: str = ""):
    require_owner()
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is not None, "Unknown vk_id!"
    replacement_vk_id = require_optional_vk_id(replacement_vk_id)
    assert replacement_vk_id != vk_id, "replacement_vk_id must differ!"
    verifying_keys[vk_id, "deprecated"] = True
    verifying_keys[vk_id, "deprecated_at"] = now
    verifying_keys[vk_id, "replacement_vk_id"] = replacement_vk_id
    VkLifecycleChanged(
        {
            "vk_id": vk_id,
            "deprecated": True,
            "replacement_vk_id": replacement_vk_id,
        }
    )
    return get_vk_info(vk_id)


@export
def restore_vk(vk_id: str):
    require_owner()
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is not None, "Unknown vk_id!"
    verifying_keys[vk_id, "deprecated"] = False
    verifying_keys[vk_id, "deprecated_at"] = None
    verifying_keys[vk_id, "replacement_vk_id"] = ""
    VkLifecycleChanged(
        {
            "vk_id": vk_id,
            "deprecated": False,
            "replacement_vk_id": "",
        }
    )
    return get_vk_info(vk_id)


@export
def set_replacement(vk_id: str, replacement_vk_id: str = ""):
    require_owner()
    require_vk_id(vk_id)
    assert verifying_keys[vk_id, "vk_hex"] is not None, "Unknown vk_id!"
    replacement_vk_id = require_optional_vk_id(replacement_vk_id)
    assert replacement_vk_id != vk_id, "replacement_vk_id must differ!"
    verifying_keys[vk_id, "replacement_vk_id"] = replacement_vk_id
    VkLifecycleChanged(
        {
            "vk_id": vk_id,
            "deprecated": verifying_keys[vk_id, "deprecated"] is True,
            "replacement_vk_id": replacement_vk_id,
        }
    )
    return get_vk_info(vk_id)


@export
def get_vk_count():
    return vk_count.get()


@export
def get_vk_id_at(index: int):
    assert isinstance(index, int), "index must be an integer!"
    assert 0 <= index < vk_count.get(), "index out of range!"
    return vk_ids[index]


@export
def list_vk_ids(start: int = 0, limit: int = 64):
    assert isinstance(start, int), "start must be an integer!"
    assert isinstance(limit, int), "limit must be an integer!"
    assert start >= 0, "start must be non-negative!"
    assert 1 <= limit <= 256, "limit out of range!"
    total = vk_count.get()
    assert start <= total, "start out of range!"

    end = start + limit
    if end > total:
        end = total

    entries = []
    for index in range(start, end):
        entries.append(vk_ids[index])
    return entries


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
        "circuit_family": verifying_keys[vk_id, "circuit_family"],
        "statement_version": verifying_keys[vk_id, "statement_version"],
        "contract_name": verifying_keys[vk_id, "contract_name"],
        "artifact_contract_name": verifying_keys[vk_id, "artifact_contract_name"],
        "tree_depth": verifying_keys[vk_id, "tree_depth"],
        "leaf_capacity": verifying_keys[vk_id, "leaf_capacity"],
        "max_inputs": verifying_keys[vk_id, "max_inputs"],
        "max_outputs": verifying_keys[vk_id, "max_outputs"],
        "setup_mode": verifying_keys[vk_id, "setup_mode"],
        "setup_ceremony": verifying_keys[vk_id, "setup_ceremony"],
        "artifact_hash": verifying_keys[vk_id, "artifact_hash"],
        "bundle_hash": verifying_keys[vk_id, "bundle_hash"],
        "warning": verifying_keys[vk_id, "warning"],
        "deprecated": verifying_keys[vk_id, "deprecated"] is True,
        "deprecated_at": verifying_keys[vk_id, "deprecated_at"],
        "replacement_vk_id": verifying_keys[vk_id, "replacement_vk_id"],
        "index": verifying_keys[vk_id, "index"],
    }
