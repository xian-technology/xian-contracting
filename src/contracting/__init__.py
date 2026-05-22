if not __debug__:
    raise RuntimeError(
        "xian-contracting refuses to run with PYTHONOPTIMIZE / python -O: "
        "assert statements guard consensus-critical invariants and stripping "
        "them can produce divergent state. Re-run without -O."
    )
