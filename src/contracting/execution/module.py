import builtins
import hashlib
import importlib
import importlib.util
import sys
from contextvars import ContextVar
from importlib import __import__, invalidate_caches
from importlib.abc import Loader
from importlib.machinery import ModuleSpec

from cachetools import LRUCache

from contracting.execution.runtime import rt
from contracting.stdlib import env
from contracting.storage.driver import Driver

# This function overrides the __import__ function, which is the builtin function that is called whenever Python runs
# an 'import' statement. If the globals dictionary contains {'__contract__': True}, then this function will make sure
# that the module being imported comes from contract storage and not from builtins or site packages.
#
# For all exec statements, we add the {'__contract__': True} _key to the globals to protect against unwanted imports.
#
# Note: anything installed with pip or in site-packages will also not work, so contract package names *must* be unique.


def is_valid_import(name):
    spec = importlib.util.find_spec(name)
    if not isinstance(spec.loader, ContractModuleLoader):
        raise ImportError(
            "module {} cannot be imported in a smart contract.".format(name)
        )


def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
    if globals is not None and globals.get("__contract__") is True:
        driver = ContractModuleFinder.current_driver()
        if driver.get_contract(name) is None:
            raise ImportError(
                "module {} cannot be imported in a smart contract.".format(name)
            )
        purge_contract_module(name)

    return __import__(name, globals, locals, fromlist, level)


def enable_restricted_imports():
    builtins.__import__ = restricted_import


#    builtins.float = ContractingDecimal


def disable_restricted_imports():
    builtins.__import__ = __import__


def uninstall_builtins():
    sys.meta_path.clear()
    sys.path_hooks.clear()
    sys.path.clear()
    sys.path_importer_cache.clear()
    invalidate_caches()


def _remove_contract_module_finders():
    sys.meta_path[:] = [
        finder for finder in sys.meta_path if finder is not ContractModuleFinder
    ]


def install_contract_module_loader(driver=None):
    if driver is None:
        driver = ContractModuleFinder.current_driver() or Driver()
    _CONTRACT_MODULE_DRIVER.set(driver)
    ContractModuleFinder.default_driver = driver
    _remove_contract_module_finders()
    sys.meta_path.insert(0, ContractModuleFinder)
    invalidate_caches()


def uninstall_contract_module_loader():
    _remove_contract_module_finders()
    invalidate_caches()


def install_system_contracts(directory=""):
    pass


def purge_contract_module(name: str) -> None:
    sys.modules.pop(name, None)


def import_contract_module(name: str):
    driver = ContractModuleFinder.current_driver()
    if driver.get_contract(name) is None:
        raise ImportError("Module {} not found".format(name))

    purge_contract_module(name)
    spec = importlib.util.find_spec(name)
    if spec is None or not isinstance(spec.loader, ContractModuleLoader):
        raise ImportError(
            "module {} cannot be imported in a smart contract.".format(name)
        )
    return importlib.import_module(name)


class ContractModuleFinder:
    default_driver = None

    @classmethod
    def current_driver(cls):
        driver = (
            rt.env.get("__Driver")
            or _CONTRACT_MODULE_DRIVER.get()
            or cls.default_driver
        )
        if driver is None:
            driver = Driver()
            cls.default_driver = driver
        return driver

    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        driver = cls.current_driver()
        if driver.get_contract(fullname) is None:
            return None
        return ModuleSpec(fullname, ContractModuleLoader(driver))


_CONTRACT_MODULE_DRIVER: ContextVar[Driver | None] = ContextVar(
    "contracting_contract_module_driver",
    default=None,
)


COMPILED_CODE_CACHE = LRUCache(maxsize=512)


def _compiled_code_cache_key(name: str, code: str) -> tuple[str, str]:
    code_hash = hashlib.sha3_256(code.encode("utf-8")).hexdigest()
    return name, code_hash


def _compile_contract_code(name: str, code: str):
    cache_key = _compiled_code_cache_key(name, code)
    compiled = COMPILED_CODE_CACHE.get(cache_key)
    if compiled is None:
        compiled = compile(code, name, "exec")
        COMPILED_CODE_CACHE[cache_key] = compiled
    return compiled


class ContractModuleLoader(Loader):
    def __init__(self, driver=None):
        self.driver = driver or ContractModuleFinder.current_driver()

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        # fetch the individual contract
        code = self.driver.get_contract(module.__name__)
        if code is None:
            raise ImportError("Module {} not found".format(module.__name__))

        compiled = _compile_contract_code(module.__name__, code)

        rt.tracer.register_code(compiled)

        scope = env.gather()
        scope.update(rt.env)

        scope.update({"__contract__": True})

        # execute the module with the std env and update the module to pass forward
        exec(compiled, scope)

        # Update the module's attributes with the new scope
        vars(module).update(scope)
        del vars(module)["__builtins__"]

        rt.loaded_modules.append(module.__name__)

    def module_repr(self, module):
        return "<module {!r} (smart contract)>".format(module.__name__)
