import builtins
from collections.abc import Callable

from contracting.compilation.attribute_guards import ATTRIBUTE_TARGET_HELPER
from contracting.compilation.format_guards import (
    FORMAT_ATTRIBUTE_HELPER,
    FORMAT_FSTRING_HELPER,
)
from contracting.compilation.whitelists import ALLOWED_BUILTINS
from contracting.execution.attribute_guards import attribute_target
from contracting.execution.format_policy import format_attribute, format_fstring
from contracting.stdlib.builtins import exports as builtin_exports


def build_contract_builtins(import_hook: Callable) -> dict[str, object]:
    allowed = {
        name: getattr(builtins, name) for name in ALLOWED_BUILTINS if hasattr(builtins, name)
    }
    allowed.update(builtin_exports)
    allowed["__import__"] = import_hook
    allowed[ATTRIBUTE_TARGET_HELPER] = attribute_target
    allowed[FORMAT_ATTRIBUTE_HELPER] = format_attribute
    allowed[FORMAT_FSTRING_HELPER] = format_fstring
    return allowed
