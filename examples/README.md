# Examples

The notebooks in this directory are kept in sync with the current
`xian-contracting` runtime.

Principles:

- Notebooks use explicit source-string submission instead of relying on live
  notebook-cell source introspection.
- Contract names follow the current runtime rule: lowercase and starting with
  `con_`.
- Human-readable contract source is inspected through `__source__`, while
  canonical runtime code is inspected through `__code__`.
- Outputs are cleared in git so the notebooks stay reviewable and rerunnable.

Run them in Jupyter as usual, or validate them without Jupyter:

```bash
uv run python examples/validate_notebooks.py
```

That validation script executes each notebook's code cells sequentially in a
fresh namespace and fails on the first error.
