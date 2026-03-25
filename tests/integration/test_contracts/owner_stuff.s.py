@export
def get_owner(s: str):
    m = importlib.import_module(s)
    return importlib.owner_of(m)


@export
def get_owner_by_name(s: str):
    return importlib.owner_of(s)


@export
def get_contract_info(s: str):
    m = importlib.import_module(s)
    return importlib.contract_info(m)


@export
def get_contract_info_by_name(s: str):
    return importlib.contract_info(s)


@export
def get_code_hash(s: str, kind: str = "runtime"):
    m = importlib.import_module(s)
    return importlib.code_hash(m, kind=kind)


@export
def get_code_hash_by_name(s: str, kind: str = "runtime"):
    return importlib.code_hash(s, kind=kind)


@export
def owner_of_this():
    return ctx.owner
