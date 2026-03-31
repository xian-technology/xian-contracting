import inspect
from functools import wraps
from contextlib import ContextDecorator
from typing import Any, get_args, get_origin

from contracting.execution.runtime import rt
from contracting.storage.driver import Driver
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta


def _annotation_label(annotation):
    if annotation is Any:
        return "Any"
    if annotation is Datetime:
        return "datetime.datetime"
    if annotation is Timedelta:
        return "datetime.timedelta"
    return str(annotation)


def _raise_type_error(label, annotation, value):
    raise TypeError(
        f"{label} must be {_annotation_label(annotation)}, "
        f"got {type(value).__name__}!"
    )


def _check_typed_value(value, annotation, label):
    if annotation is inspect.Signature.empty or annotation is Any:
        return

    origin = get_origin(annotation)
    if origin is list:
        if not isinstance(value, list):
            _raise_type_error(label, annotation, value)
        args = get_args(annotation)
        if args:
            item_annotation = args[0]
            for index, item in enumerate(value):
                _check_typed_value(
                    item,
                    item_annotation,
                    f"{label}[{index}]",
                )
        return

    if origin is dict:
        if not isinstance(value, dict):
            _raise_type_error(label, annotation, value)
        args = get_args(annotation)
        if len(args) >= 2:
            key_annotation, value_annotation = args[:2]
            for key, item in value.items():
                _check_typed_value(
                    key,
                    key_annotation,
                    f"{label} key",
                )
                _check_typed_value(
                    item,
                    value_annotation,
                    f"{label}[{key!r}]",
                )
        return

    if annotation is bool:
        if type(value) is not bool:
            _raise_type_error(label, annotation, value)
        return

    if annotation is int:
        if type(value) is not int:
            _raise_type_error(label, annotation, value)
        return

    if annotation is float:
        if isinstance(value, bool) or not isinstance(
            value, (int, float, ContractingDecimal)
        ):
            _raise_type_error(label, annotation, value)
        return

    if annotation is list:
        if not isinstance(value, list):
            _raise_type_error(label, annotation, value)
        return

    if annotation is dict:
        if not isinstance(value, dict):
            _raise_type_error(label, annotation, value)
        return

    if not isinstance(value, annotation):
        _raise_type_error(label, annotation, value)


class __export(ContextDecorator):
    def __init__(self, contract, typecheck=False):
        self.contract = contract
        self.typecheck = typecheck

    def __call__(self, func):
        signature = inspect.signature(func)
        annotations = dict(func.__annotations__)

        @wraps(func)
        def wrapper(*args, **kwargs):
            if self.typecheck:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()

                for name, value in bound.arguments.items():
                    annotation = annotations.get(name, inspect.Signature.empty)
                    _check_typed_value(value, annotation, f"Argument '{name}'")

            with self._recreate_cm():
                result = func(*args, **kwargs)

            if self.typecheck:
                _check_typed_value(
                    result,
                    annotations.get("return", inspect.Signature.empty),
                    "Return value",
                )

            return result

        return wrapper

    def __enter__(self, *args, **kwargs):
        driver = rt.env.get("__Driver") or Driver()

        if rt.context._context_changed(self.contract):
            current_state = rt.context._get_state()

            state = {
                "owner": driver.get_owner(self.contract),
                "caller": current_state["this"],
                "signer": current_state["signer"],
                "this": self.contract,
                "entry": current_state["entry"],
                "submission_name": current_state["submission_name"],
            }

            if state["owner"] is not None and state["owner"] != state["caller"]:
                raise Exception("Caller is not the owner!")

            rt.context._add_state(state)
        else:
            rt.context._ins_state()

        rt.enter_contract_metering(self.contract)

    def __exit__(self, *args, **kwargs):
        rt.exit_contract_metering()
        rt.context._pop_state()


exports = {"__export": __export, "ctx": rt.context, "rt": rt, "Any": Any}
