from contracting.execution.runtime import rt
from contracting.storage.contract import Contract
from contracting.storage.orm import (
    ForeignHash,
    ForeignVariable,
    Hash,
    LogEvent,
    Variable,
    indexed,
)


class V(Variable):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class H(Hash):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class FV(ForeignVariable):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class FH(ForeignHash):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class C(Contract):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


class LE(LogEvent):
    def __init__(self, *args, **kwargs):
        if rt.env.get("__Driver") is not None:
            kwargs["driver"] = rt.env.get("__Driver")
        super().__init__(*args, **kwargs)


# Define the locals that will be available for smart contracts at runtime
exports = {
    "Variable": V,
    "Hash": H,
    "ForeignVariable": FV,
    "ForeignHash": FH,
    "LogEvent": LE,
    "indexed": indexed,
    "Contract": C,
    "__Contract": C,
}
