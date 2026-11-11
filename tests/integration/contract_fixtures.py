"""Authored fixture sources submitted through the real native submission contract."""

from pathlib import Path

SUBMIT_CONTRACT = {
    "sender": "stu",
    "contract_name": "submission",
    "function_name": "submit_contract",
}


def submission_kwargs_for_file(path):
    path = Path(path)
    return {"name": f"con_{path.name.split('.', 1)[0]}", "code": path.read_text()}
