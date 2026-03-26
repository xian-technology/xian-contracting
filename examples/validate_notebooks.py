import json
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def iter_notebooks():
    yield from sorted(ROOT.glob("*.ipynb"))


def execute_notebook(path: Path) -> None:
    notebook = json.loads(path.read_text())
    namespace = {"__name__": "__main__"}

    for index, cell in enumerate(notebook["cells"]):
        if cell.get("cell_type") != "code":
            continue

        source = "".join(cell.get("source", []))
        if not source.strip():
            continue

        exec(
            compile(source, f"{path.name}:cell{index}", "exec"),
            namespace,
            namespace,
        )


def main() -> int:
    for path in iter_notebooks():
        print(f"=== {path.name} ===")
        try:
            execute_notebook(path)
        except Exception:
            traceback.print_exc(limit=6)
            return 1
        print("OK")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
