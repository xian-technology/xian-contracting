from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.execution.runtime import rt
from contracting.stdlib import env
from contracting.storage.driver import Driver


class Contract:
    def __init__(self, driver: Driver | None = None):
        self._driver = driver or rt.env.get("__Driver") or Driver()

    def submit(
        self,
        name,
        code,
        owner=None,
        constructor_args=None,
        developer=None,
        deployer=None,
        initiator=None,
    ):
        with rt.execution_lock:
            if self._driver.get_contract(name) is not None:
                raise Exception("Contract already exists.")

            if not isinstance(code, str):
                raise TypeError("Contract code must be a string.")

            raw_source_bytes = len(code.encode("utf-8"))
            assert (
                raw_source_bytes <= constants.MAX_CONTRACT_SUBMISSION_BYTES
            ), "Contract source exceeds the maximum allowed size."

            c = ContractingCompiler(module_name=name)

            source_obj = c.normalize_source(code, lint=False)
            rt.deduct_execution_cost(
                constants.DEPLOYMENT_BASE_COST
                + (
                    len(source_obj.encode("utf-8"))
                    * constants.DEPLOYMENT_COST_PER_SOURCE_BYTE
                )
            )
            code_obj = c.parse_to_code(code, lint=True)

            scope = env.gather()
            scope.update({"__contract__": True})
            scope.update(rt.env)

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

            with rt.push_context_state(deployment_state):
                exec(compiled, scope)

                if scope.get(constants.INIT_FUNC_NAME) is not None:
                    if constructor_args is None:
                        constructor_args = {}
                    scope[constants.INIT_FUNC_NAME](**constructor_args)

            now = scope.get("now")
            if now is not None:
                self._driver.set_contract(
                    name=name,
                    code=code_obj,
                    source=source_obj,
                    owner=owner,
                    overwrite=False,
                    timestamp=now,
                    developer=deployment_developer,
                    deployer=deployment_deployer,
                    initiator=deployment_initiator,
                )
            else:
                self._driver.set_contract(
                    name=name,
                    code=code_obj,
                    source=source_obj,
                    owner=owner,
                    overwrite=False,
                    developer=deployment_developer,
                    deployer=deployment_deployer,
                    initiator=deployment_initiator,
                )
