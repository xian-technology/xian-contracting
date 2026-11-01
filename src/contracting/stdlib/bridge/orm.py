from contracting.execution.runtime import consume_orm_declaration, orm_declaration_scope, rt
from contracting.storage.contract import Contract
from contracting.storage.orm import (
    ForeignHash,
    ForeignVariable,
    Hash,
    LogEvent,
    Variable,
    indexed,
)


class _StorageDeclaration:
    def __init__(self, *args, **kwargs):
        consume_orm_declaration(type(self), kwargs.get("contract"), kwargs.get("name"))
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class V(_StorageDeclaration, Variable):
    pass


class H(_StorageDeclaration, Hash):
    pass


class FV(_StorageDeclaration, ForeignVariable):
    pass


class FH(_StorageDeclaration, ForeignHash):
    pass


class C(Contract):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class LE(_StorageDeclaration, LogEvent):
    pass


def declare_orm(storage_class, contract, name, /, *args, **kwargs):
    """Private compiler helper: arguments are evaluated before authority exists."""
    if not any(storage_class is cls for cls in (V, H, FV, FH, LE)):
        raise TypeError("Invalid storage declaration class.")
    with orm_declaration_scope(storage_class, contract, name):
        return storage_class(*args, contract=contract, name=name, **kwargs)


def declare_foreign_orm(storage_class, contract, name, /, *args, **kwargs):
    """Function-local references are limited to the two read-only classes."""
    if storage_class is not FV and storage_class is not FH:
        raise TypeError("Dynamic storage references must be read-only foreign declarations.")
    return declare_orm(storage_class, contract, name, *args, **kwargs)


# Define the locals that will be available for smart contracts at runtime
exports = {
    "__xian_orm_declaration__": declare_orm,
    "__xian_foreign_declaration__": declare_foreign_orm,
    "Variable": V,
    "Hash": H,
    "ForeignVariable": FV,
    "ForeignHash": FH,
    "LogEvent": LE,
    "indexed": indexed,
    "Contract": C,
    "__Contract": C,
}
