import sys

from contracting import constants

if not __debug__:
    raise RuntimeError(
        "xian-contracting refuses to run with PYTHONOPTIMIZE / python -O: "
        "assert statements guard consensus-critical invariants and stripping "
        "them can produce divergent state. Re-run without -O."
    )

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(constants.MAX_INT_STRING_CHARS)
