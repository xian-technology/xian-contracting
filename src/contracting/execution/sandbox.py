import builtins
from collections.abc import Callable

from contracting.compilation.whitelists import ALLOWED_BUILTINS
from contracting.stdlib.builtins import exports as builtin_exports


def build_contract_builtins(import_hook: Callable) -> dict[str, object]:
    allowed = {
        name: getattr(builtins, name)
        for name in ALLOWED_BUILTINS
        if hasattr(builtins, name)
    }
    allowed.update(builtin_exports)
    allowed["__import__"] = import_hook
    return allowed
