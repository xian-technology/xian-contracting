@export
def get_owner(s: str):
    m = importlib.import_module(s)
    return importlib.owner_of(m)


@export
def get_owner_by_name(s: str):
    return importlib.owner_of(s)


@export
def owner_of_this():
    return ctx.owner
