import importlib
import inspect
import sys
from types import FunctionType, ModuleType

from contracting.constants import PRIVATE_METHOD_PREFIX
from contracting.execution.runtime import rt
from contracting.stdlib.bridge.access import __export
from contracting.storage.driver import OWNER_KEY, Driver
from contracting.storage.orm import Datum


def extract_closure(fn):
    closure = fn.__closure__[0]
    return closure.cell_contents


class Func:
    def __init__(self, name, args=(), private=False):
        self.name = name

        if private:
            self.name = PRIVATE_METHOD_PREFIX + self.name

        self.args = args

    def is_of(self, f: FunctionType):

        if f.__closure__ is not None:
            f = extract_closure(f)

        num_args = f.__code__.co_argcount

        if (
            f.__code__.co_name == self.name
            and f.__code__.co_varnames[:num_args] == self.args
        ):
            return True

        return False


class Var:
    def __init__(self, name, t):
        self.name = PRIVATE_METHOD_PREFIX + name
        assert issubclass(t, Datum), (
            "Cannot enforce a variable that is not a Variable, Hash, or Foreign type!"
        )
        self.type = t

    def is_of(self, v):
        if isinstance(v, self.type):
            return True
        return False


def _contract_name_is_valid(name):
    if not isinstance(name, str):
        return False
    if name.isdigit():
        return False
    if not all(c.isalnum() or c == "_" for c in name):
        return False
    if not name.islower():
        return False
    if name in set(
        list(sys.stdlib_module_names) + list(sys.builtin_module_names)
    ):
        return False
    if name.startswith("_"):
        return False
    return True


def _contract_exists_by_name(name):
    if not _contract_name_is_valid(name):
        return False

    _driver = rt.env.get("__Driver") or Driver()
    return _driver.get_contract(name) is not None


def import_module(name):
    assert _contract_name_is_valid(name), "Invalid contract name!"

    if not _contract_exists_by_name(name):
        raise ImportError

    return importlib.import_module(name, package=None)


def _resolve_contract_module(contract):
    if isinstance(contract, str):
        return import_module(contract)

    if not isinstance(contract, ModuleType):
        raise AssertionError(
            "Contract target must be a contract name or imported contract module!"
        )

    _driver = rt.env.get("__Driver") or Driver()
    if _driver.get_contract(contract.__name__) is None:
        raise AssertionError(
            "Contract module must reference an existing deployed contract!"
        )

    return contract


def exists(contract):
    if isinstance(contract, str):
        return _contract_exists_by_name(contract)

    if not isinstance(contract, ModuleType):
        raise AssertionError(
            "Contract target must be a contract name or imported contract module!"
        )

    _driver = rt.env.get("__Driver") or Driver()
    return _driver.get_contract(contract.__name__) is not None


def _validate_function_name(name):
    if not isinstance(name, str):
        raise AssertionError("Function name must be a string!")
    if name == "":
        raise AssertionError("Function name must not be empty!")
    if not name.isidentifier():
        raise AssertionError("Function name must be a valid identifier!")
    if name.startswith(PRIVATE_METHOD_PREFIX):
        raise AssertionError("Private functions cannot be called dynamically!")
    if name.startswith("_") or name.endswith("_"):
        raise AssertionError(
            "Dynamic function names cannot start or end with '_'!"
        )


def _unwrap_exported_function(attribute):
    if not isinstance(attribute, FunctionType):
        raise AssertionError(
            "Dynamic calls may only target exported contract functions!"
        )

    closure = attribute.__closure__ or ()
    original = None
    export_guard = None
    for cell in closure:
        value = cell.cell_contents
        if isinstance(value, FunctionType):
            original = value
        elif isinstance(value, __export):
            export_guard = value

    if original is None or export_guard is None:
        raise AssertionError(
            "Dynamic calls may only target exported contract functions!"
        )

    return attribute, original, export_guard


def _resolve_exported_function(module, function_name):
    attribute = vars(module).get(function_name)
    if attribute is None:
        raise AssertionError(
            f"Exported function '{function_name}' does not exist on contract '{module.__name__}'!"
        )

    wrapper, original, export_guard = _unwrap_exported_function(attribute)

    if original.__code__.co_name != function_name:
        raise AssertionError(
            f"Dynamic call target '{function_name}' is not a valid exported function!"
        )

    if export_guard.contract != module.__name__:
        raise AssertionError(
            f"Dynamic call target '{function_name}' is not a valid exported function!"
        )

    return wrapper, original


def _validate_dynamic_kwargs(module_name, function_name, original, kwargs):
    if kwargs is None:
        return {}

    if not isinstance(kwargs, dict):
        raise AssertionError("Dynamic call kwargs must be a dict!")

    for key in kwargs:
        if not isinstance(key, str):
            raise AssertionError("Dynamic call kwargs keys must be strings!")

    try:
        inspect.signature(original).bind(**kwargs)
    except TypeError as exc:
        raise AssertionError(
            f"Invalid kwargs for {module_name}.{function_name}: {exc}"
        ) from exc

    return kwargs


def call(contract, function, kwargs=None):
    module = _resolve_contract_module(contract)
    _validate_function_name(function)
    wrapper, original = _resolve_exported_function(module, function)
    kwargs = _validate_dynamic_kwargs(
        module.__name__, function, original, kwargs
    )
    return wrapper(**kwargs)


def has_export(contract, function):
    try:
        module = _resolve_contract_module(contract)
    except (AssertionError, ImportError):
        return False

    if not isinstance(function, str):
        raise AssertionError("Function name must be a string!")

    if (
        function == ""
        or not function.isidentifier()
        or function.startswith(PRIVATE_METHOD_PREFIX)
        or function.startswith("_")
        or function.endswith("_")
    ):
        return False

    try:
        _resolve_exported_function(module, function)
    except AssertionError:
        return False

    return True


def enforce_interface(m: ModuleType, interface: list):
    implemented = vars(m)

    for i in interface:
        attribute = implemented.get(i.name)
        if attribute is None:
            return False

        # Branch for data types
        if isinstance(attribute, Datum):
            if not i.is_of(attribute):
                return False

        if isinstance(attribute, FunctionType):
            if not i.is_of(attribute):
                return False

    return True


def owner_of(m: ModuleType):
    _driver = rt.env.get("__Driver") or Driver()
    owner = _driver.get_var(m.__name__, OWNER_KEY)
    return owner


imports_module = ModuleType("importlib")
imports_module.import_module = import_module
imports_module.exists = exists
imports_module.has_export = has_export
imports_module.call = call
imports_module.enforce_interface = enforce_interface
imports_module.Func = Func
imports_module.Var = Var
imports_module.owner_of = owner_of

exports = {
    "importlib": imports_module,
}
