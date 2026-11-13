from __future__ import annotations

import ast
import inspect
import json
import os
import textwrap
from datetime import datetime
from functools import partial
from pathlib import Path
from types import FunctionType

from xian_runtime_types.time import Datetime

from contracting import constants
from contracting.artifacts import (
    DEFAULT_VM_PROFILE,
    XIAN_VM_V2_PROFILE,
    build_contract_artifacts,
    compile_contract_source,
    diagnose_contract_source,
)
from contracting.local.native_executor import NativeExecutor
from contracting.storage.driver import Driver
from contracting.storage.orm import Hash, Variable

BUILTIN_SUBMISSION_SOURCE_PATH = (
    Path(__file__).resolve().parents[1] / "contracts" / "submission_source.s.py"
)


class AbstractContract:
    def __init__(
        self,
        name,
        signer,
        environment,
        executor: NativeExecutor,
        funcs,
        return_full_output=False,
    ):
        self.name = name
        self.signer = signer
        self.environment = environment
        self.executor = executor
        self.functions = funcs

        for func, _ in funcs:
            setattr(
                self,
                func,
                partial(
                    self._abstract_function_call,
                    signer=self.signer,
                    contract_name=self.name,
                    executor=self.executor,
                    func=func,
                    return_full_output=return_full_output,
                ),
            )

    def keys(self):
        # Scope strictly to this contract's namespace
        return self.executor.driver.keys(f"{self.name}.")

    # a variable contains a DOT, but no __, and no :
    # a hash contains a DOT, no __, and a :
    # a constant contains __, a DOT, and :

    def quick_read(self, variable, key=None, args=None):
        a = []

        if key is not None:
            a.append(key)

        if args is not None and isinstance(args, list):
            for arg in args:
                a.append(arg)

        k = self.executor.driver.make_key(contract=self.name, variable=variable, args=a)
        return self.executor.driver.get(k)

    def quick_write(self, variable, key=None, value=None, args=None):
        if key is not None:
            a = [key]
        else:
            a = []

        if args is not None and isinstance(args, list):
            for arg in args:
                a.append(arg)

        k = self.executor.driver.make_key(contract=self.name, variable=variable, args=a)

        self.executor.driver.set(k, value)
        self.executor.driver.commit()

    def __getattr__(self, item):
        try:
            # return the attribute if it exists on the instance
            return self.__getattribute__(item)
        except AttributeError as e:
            # otherwise, attempt to resolve it. full name is contract.item
            fullname = "{}.{}".format(self.name, item)

            # if the raw name exists, it is a __protected__ or a variable, so prepare for those
            if fullname in self.keys():
                variable = Variable(contract=self.name, name=item, driver=self.executor.driver)

                # return just the value if it is __protected__ to prevent sets
                if item.startswith("__"):
                    return variable.get()

                # otherwise, return the variable object with allows sets
                return variable

            # otherwise, see if contract.items: has more than one entry
            if len(self.executor.driver.values(prefix=self.name + "." + item + ":")) > 0:
                # if so, it is a hash. return the hash object
                return Hash(contract=self.name, name=item, driver=self.executor.driver)

            # otherwise, the attribut does not exist, so throw the error.
            raise e

    def now(self):
        d = datetime.today()
        return Datetime(d.year, d.month, d.day, hour=d.hour, minute=d.minute)

    def _abstract_function_call(
        self,
        signer,
        executor,
        contract_name,
        func,
        return_full_output,
        environment=None,
        chi=constants.DEFAULT_CHI,
        metering=None,
        now=None,
        **kwargs,
    ):

        environment = dict(environment or self.environment)

        if now is None:
            now = self.now()

        if environment.get("now") is None:
            environment.update({"now": now})

        output = executor.execute(
            sender=signer,
            contract_name=contract_name,
            function_name=func,
            kwargs=kwargs,
            chi=chi,
            environment=environment,
            metering=metering,
        )

        if output["status_code"] == 1 and not return_full_output:
            raise output["result"]
        return output["result"] if not return_full_output else output


class ContractingClient:
    def __init__(
        self,
        signer="sys",
        submission_filename=str(BUILTIN_SUBMISSION_SOURCE_PATH),
        storage_home=None,
        driver: Driver | None = None,
        metering=False,
        environment: dict | None = None,
        vm_profile: str | None = None,
    ):
        self.vm_profile = (
            vm_profile
            if vm_profile is not None
            else (driver.vm_profile if driver is not None else DEFAULT_VM_PROFILE)
        )
        if self.vm_profile != XIAN_VM_V2_PROFILE:
            raise ValueError("ContractingClient only supports xian_vm_v2")
        if driver is not None and driver.vm_profile != self.vm_profile:
            raise ValueError("client and storage driver profiles must match")
        self._owns_driver = driver is None
        driver = (
            driver
            if driver is not None
            else Driver(storage_home=storage_home, vm_profile=self.vm_profile)
        )
        self.executor = NativeExecutor(driver, metering=metering)
        self.raw_driver = driver
        self.signer = signer
        self.submission_filename = submission_filename
        self.environment = environment if environment is not None else {}
        try:
            self._initialize_submission()
        except BaseException:
            self.close()
            raise

    def _initialize_submission(self):
        if self.submission_filename is not None:
            source_code, vm_ir_json = self._load_submission_artifacts(self.submission_filename)
            self.raw_driver.set_contract(
                name="submission",
                source=source_code,
                vm_ir_json=vm_ir_json,
            )
            self.raw_driver.commit()
        self.submission_contract = self.get_contract_proxy("submission")

    def close(self) -> None:
        if self._owns_driver:
            self.raw_driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def set_submission_contract(self, filename=None, commit=True):
        state_contract = self.get_contract_proxy("submission")

        if filename is None:
            filename = self.submission_filename

        if filename is None and state_contract is None:
            raise AssertionError("No submission contract provided or found in state.")

        if filename is not None:
            source_code, vm_ir_json = self._load_submission_artifacts(filename)
            self.raw_driver.delete_contract(name="submission")
            self.raw_driver.set_contract(
                name="submission",
                source=source_code,
                vm_ir_json=vm_ir_json,
            )

            if commit:
                self.raw_driver.commit()

        self.submission_contract = self.get_contract_proxy("submission")

    def _load_submission_artifacts(
        self,
        filename: str | os.PathLike[str],
    ) -> tuple[str, str]:
        source_code = Path(filename).resolve().read_text(encoding="utf-8")
        compiled = compile_contract_source(
            module_name="submission", source=source_code, vm_profile=self.vm_profile
        )
        return compiled["source"], compiled["vm_ir_json"]

    def flush(self):
        # flushes storage and resubmits genesis contracts
        self.raw_driver.flush_full()
        self.raw_driver.flush_cache()

        if self.submission_filename is not None:
            self.set_submission_contract()

    # Returns abstract contract which has partial methods mapped to each exported function.
    def get_contract_proxy(self, name):
        ir = self.raw_driver.get_contract_ir(name)
        if ir is None:
            return None
        funcs = [
            (function["name"], [param["name"] for param in function["parameters"]])
            for function in json.loads(ir)["functions"]
            if function["visibility"] == "export"
        ]

        return AbstractContract(
            name=name,
            signer=self.signer,
            environment=self.environment,
            executor=self.executor,
            funcs=funcs,
        )

    def get_contract_source(self, name):
        return self.raw_driver.get_contract_source(name)

    def get_contract_ir(self, name, *, vm_profile: str | None = None):
        return self.raw_driver.get_contract_ir(name, vm_profile=vm_profile)

    def closure_to_code_string(self, f):
        closure_code = textwrap.dedent(inspect.getsource(f))
        closure_tree = ast.parse(closure_code)

        # Remove the enclosing function by swapping out the function def node with its children
        assert len(closure_tree.body) == 1, "Module has multiple body nodes."
        assert isinstance(closure_tree.body[0], ast.FunctionDef), (
            "Function definition not found at root."
        )

        func_def_body = closure_tree.body[0]
        # Preserve original literal digits when the caller submits a Python function.
        first = func_def_body.body[0]
        decorators = getattr(first, "decorator_list", [])
        start = min([first.lineno, *(d.lineno for d in decorators)]) - 1
        return textwrap.dedent(
            "".join(closure_code.splitlines(keepends=True)[start:])
        ), func_def_body.name

    def lint(self, f, raise_errors=False):
        if isinstance(f, FunctionType):
            f, _ = self.closure_to_code_string(f)

        diagnostics = diagnose_contract_source(
            module_name="con_lint", source=f, vm_profile=self.vm_profile
        )
        if raise_errors and diagnostics:
            raise ValueError(diagnostics[0]["message"])
        return diagnostics or None

    def compile(self, f):
        if isinstance(f, FunctionType):
            f, _ = self.closure_to_code_string(f)

        return compile_contract_source(
            module_name="con_compile", source=f, vm_profile=self.vm_profile
        )["source"]

    def build_contract_artifacts(self, f, *, name=None):
        if isinstance(f, FunctionType):
            f, inferred_name = self.closure_to_code_string(f)
            if name is None:
                name = inferred_name

        assert name is not None, "No name provided."

        return build_contract_artifacts(
            module_name=name,
            source=f,
            vm_profile=self.vm_profile,
        )

    def submit(
        self,
        f,
        name=None,
        metering=None,
        owner=None,
        constructor_args=None,
        signer=None,
    ):
        if constructor_args is None:
            constructor_args = {}

        if self.raw_driver.has_contract("submission"):
            self.submission_contract = self.get_contract_proxy("submission")

        assert self.submission_contract is not None, (
            "No submission contract set. Try set_submission_contract first."
        )

        if isinstance(f, FunctionType):
            f, n = self.closure_to_code_string(f)
            if name is None:
                name = n

        assert name is not None, "No name provided."

        if signer is None:
            signer = self.signer

        self.submission_contract.submit_contract(
            name=name,
            code=f,
            owner=owner,
            constructor_args=constructor_args,
            metering=metering,
            signer=signer,
        )

    def get_contracts(self):
        contracts = set()
        for key in self.raw_driver.keys():
            if key.endswith(".__source__"):
                contracts.add(key.replace(".__source__", ""))
            elif key.endswith(".__xian_ir_v1__"):
                contracts.add(key.replace(".__xian_ir_v1__", ""))
        return sorted(contracts)

    def get_var(self, contract, variable, arguments=None):
        if arguments is None:
            arguments = []
        return self.raw_driver.get_var(contract, variable, arguments)

    def set_var(self, contract, variable, arguments=None, value=None):
        if arguments is None:
            arguments = []
        self.raw_driver.set_var(contract, variable, arguments, value)
