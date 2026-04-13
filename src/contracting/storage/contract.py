from contracting import constants
from contracting.compilation.artifacts import (
    build_contract_artifacts,
    validate_contract_artifacts,
)
from contracting.execution.runtime import rt
from contracting.names import assert_safe_contract_name
from contracting.storage.driver import (
    DEVELOPER_KEY,
    DEPLOYER_KEY,
    INITIATOR_KEY,
    OWNER_KEY,
    TIME_KEY,
    Driver,
)

XIAN_EXECUTION_MODE_ENV_KEY = "__xian_execution_mode__"


class Contract:
    def __init__(self, driver: Driver | None = None):
        self._driver = driver or rt.env.get("__Driver") or Driver()

    @staticmethod
    def _resolve_driver(driver: Driver | None = None) -> Driver:
        return driver or rt.env.get("__Driver") or Driver()

    @classmethod
    def _submit_with_driver(
        cls,
        driver: Driver,
        *,
        name,
        code,
        deployment_artifacts=None,
        owner=None,
        constructor_args=None,
        developer=None,
        deployer=None,
        initiator=None,
    ):
        with rt.execution_lock:
            assert_safe_contract_name(name)

            if driver.get_contract(name) is not None:
                raise Exception("Contract already exists.")

            if code is None and deployment_artifacts is None:
                raise TypeError(
                    "Contract deployment requires code or deployment_artifacts."
                )
            if code is not None and not isinstance(code, str):
                raise TypeError("Contract code must be a string.")
            if (
                deployment_artifacts is None
                and rt.env.get(XIAN_EXECUTION_MODE_ENV_KEY) == "xian_vm_v1"
            ):
                raise TypeError(
                    "xian_vm_v1 requires deployment_artifacts for contract deployment."
                )

            if deployment_artifacts is not None:
                artifacts = validate_contract_artifacts(
                    module_name=name,
                    artifacts=deployment_artifacts,
                    input_source=code,
                    vm_profile="xian_vm_v1",
                )
            else:
                artifacts = build_contract_artifacts(
                    module_name=name,
                    source=code,
                    lint=True,
                    vm_profile="xian_vm_v1",
                )

            if (
                artifacts["runtime_code"] is None
                or artifacts["vm_ir_json"] is None
            ):
                derived = build_contract_artifacts(
                    module_name=name,
                    source=artifacts["source"],
                    lint=False,
                    vm_profile="xian_vm_v1",
                )
                artifacts["runtime_code"] = derived["runtime_code"]
                artifacts["vm_ir_json"] = derived["vm_ir_json"]

            source_obj = artifacts["source"]
            code_obj = artifacts["runtime_code"]
            vm_ir_json = artifacts["vm_ir_json"]

            raw_source_bytes = len(source_obj.encode("utf-8"))
            assert (
                raw_source_bytes <= constants.MAX_CONTRACT_SUBMISSION_BYTES
            ), "Contract source exceeds the maximum allowed size."

            rt.deduct_execution_cost(
                constants.DEPLOYMENT_BASE_COST
                + (
                    len(source_obj.encode("utf-8"))
                    * constants.DEPLOYMENT_COST_PER_SOURCE_BYTE
                )
            )

            from contracting.stdlib import env

            scope = env.gather()
            scope.update({"__contract__": True})
            scope.update(rt.env)
            scope.update({"__Driver": driver})

            compiled = compile(code_obj, name, "exec")
            rt.tracer.register_code(compiled)
            current_state = rt.context._get_state()
            deployment_owner = owner
            deployment_developer = (
                current_state["caller"] if developer is None else developer
            )
            deployment_deployer = (
                current_state["caller"] if deployer is None else deployer
            )
            deployment_initiator = (
                current_state["signer"] if initiator is None else initiator
            )
            deployment_state = {
                "owner": deployment_owner,
                "caller": deployment_deployer,
                "signer": deployment_initiator,
                "this": name,
                "entry": current_state["entry"],
                "submission_name": name,
            }

            previous_driver = rt.env.get("__Driver")
            rt.env.update({"__Driver": driver})
            try:
                with rt.push_context_state(deployment_state):
                    exec(compiled, scope)

                    if scope.get(constants.INIT_FUNC_NAME) is not None:
                        if constructor_args is None:
                            constructor_args = {}
                        scope[constants.INIT_FUNC_NAME](**constructor_args)
            finally:
                if previous_driver is None:
                    rt.env.pop("__Driver", None)
                else:
                    rt.env.update({"__Driver": previous_driver})

            now = scope.get("now")
            if now is not None:
                driver.set_contract(
                    name=name,
                    code=code_obj,
                    source=source_obj,
                    vm_ir_json=vm_ir_json,
                    owner=owner,
                    overwrite=False,
                    timestamp=now,
                    developer=deployment_developer,
                    deployer=deployment_deployer,
                    initiator=deployment_initiator,
                )
            else:
                driver.set_contract(
                    name=name,
                    code=code_obj,
                    source=source_obj,
                    vm_ir_json=vm_ir_json,
                    owner=owner,
                    overwrite=False,
                    developer=deployment_developer,
                    deployer=deployment_deployer,
                    initiator=deployment_initiator,
                )

    def submit(
        self,
        name,
        code,
        deployment_artifacts=None,
        owner=None,
        constructor_args=None,
        developer=None,
        deployer=None,
        initiator=None,
    ):
        self._submit_with_driver(
            self._driver,
            name=name,
            code=code,
            deployment_artifacts=deployment_artifacts,
            owner=owner,
            constructor_args=constructor_args,
            developer=developer,
            deployer=deployer,
            initiator=initiator,
        )

    @classmethod
    def deploy(
        cls,
        *,
        name,
        code,
        deployment_artifacts=None,
        owner=None,
        constructor_args=None,
        developer=None,
        deployer=None,
        initiator=None,
        driver: Driver | None = None,
    ):
        cls._submit_with_driver(
            cls._resolve_driver(driver),
            name=name,
            code=code,
            deployment_artifacts=deployment_artifacts,
            owner=owner,
            constructor_args=constructor_args,
            developer=developer,
            deployer=deployer,
            initiator=initiator,
        )

    @classmethod
    def get_info(cls, name: str, *, driver: Driver | None = None) -> dict:
        assert_safe_contract_name(name)
        resolved_driver = cls._resolve_driver(driver)
        return {
            "name": name,
            "owner": resolved_driver.get_var(name, OWNER_KEY),
            "developer": resolved_driver.get_var(name, DEVELOPER_KEY),
            "deployer": resolved_driver.get_var(name, DEPLOYER_KEY),
            "initiator": resolved_driver.get_var(name, INITIATOR_KEY),
            "submitted": resolved_driver.get_var(name, TIME_KEY),
        }

    @classmethod
    def set_owner(
        cls,
        name: str,
        new_owner: str,
        *,
        driver: Driver | None = None,
    ) -> None:
        assert_safe_contract_name(name)
        cls._resolve_driver(driver).set_var(
            name,
            OWNER_KEY,
            value=new_owner,
        )

    @classmethod
    def set_developer(
        cls,
        name: str,
        new_developer: str,
        *,
        driver: Driver | None = None,
    ) -> None:
        assert_safe_contract_name(name)
        cls._resolve_driver(driver).set_var(
            name,
            DEVELOPER_KEY,
            value=new_developer,
        )
