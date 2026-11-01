"""Keep authored attribute mutations local to mutable interface descriptors."""


def attribute_target(value, name):
    # Lazy import avoids compiler -> sandbox -> bridge -> compiler cycles.
    from contracting.stdlib.bridge.imports import Func, Var

    if name.startswith("_"):
        raise TypeError("private attributes are not available to contracts")
    if type(value) not in (Func, Var):
        raise TypeError("attribute assignment requires an interface descriptor")
    return value
