import decimal
from copy import deepcopy

from xian_runtime_types.decimal import CONTEXT, ContractingDecimal

from contracting import constants
from contracting.execution import runtime
from contracting.execution.module import (
    disable_restricted_imports,
    enable_restricted_imports,
    import_contract_module,
    install_contract_module_loader,
    uninstall_builtins,
)
from contracting.execution.tracer_common import (
    CallLimitExceededError,
    ChiExceededError,
)
from contracting.stdlib.bridge.random import clear_random_state
from contracting.storage.driver import Driver


def _classify_execution_error(error: BaseException | None) -> str:
    """
    Classify an execution error so callers can distinguish resource-limit
    failures from contract-level bugs. Returned value goes into the
    transaction output dict as ``error_class``.

    Categories:
      * ``"success"``              – no error (status_code == 0)
      * ``"chi_exceeded"``         – ran out of chi budget
      * ``"call_limit_exceeded"``  – deterministic instruction cap hit
      * ``"contract_assertion"``   – ``assert`` statement failed in a contract
      * ``"contract_error"``       – any other exception from contract code
    """
    if error is None:
        return "success"
    if isinstance(error, ChiExceededError):
        return "chi_exceeded"
    if isinstance(error, CallLimitExceededError):
        return "call_limit_exceeded"
    if isinstance(error, AssertionError):
        return "contract_assertion"
    return "contract_error"


class Executor:
    def __init__(
        self,
        production=False,
        driver=None,
        metering=True,
        currency_contract="currency",
        balances_hash="balances",
        bypass_privates=False,
        bypass_balance_amount=False,
        bypass_cache=False,
    ):

        self.metering = metering
        self.driver = driver

        if not self.driver:
            self.driver = Driver(bypass_cache=bypass_cache)
        self.production = production

        self.currency_contract = currency_contract
        self.balances_hash = balances_hash

        self.bypass_privates = bypass_privates
        self.bypass_balance_amount = bypass_balance_amount  # For Chi Estimation

    def wipe_modules(self):
        uninstall_builtins()
        install_contract_module_loader()

    @staticmethod
    def _coerce_balance_value(balance):
        if isinstance(balance, ContractingDecimal):
            return balance
        if isinstance(balance, dict):
            return ContractingDecimal(balance.get("__fixed__"))
        if balance is None:
            return 0
        if isinstance(balance, str | float | decimal.Decimal):
            return ContractingDecimal(str(balance))
        return balance

    def execute(
        self,
        sender,
        contract_name,
        function_name,
        kwargs,
        environment=None,
        auto_commit=False,
        driver=None,
        chi=constants.DEFAULT_CHI,
        chi_cost=constants.CHI_PER_T,
        metering=None,
        transaction_size_bytes: int = 0,
    ) -> dict:
        # Execution mutates Python's process-global import hooks and module
        # cache. Keep one in-process execution active at a time; xian-abci
        # parallelism uses separate worker processes, so this does not reduce
        # node-side speculative parallel execution.
        with runtime.rt.execution_lock:
            current_driver_pending_writes = deepcopy(self.driver.pending_writes)
            self.driver.clear_transaction_reads()
            self.driver.clear_transaction_writes()
            self.driver.clear_events()
            environment = {} if environment is None else dict(environment)

            if not self.bypass_privates:
                assert not function_name.startswith(
                    constants.PRIVATE_METHOD_PREFIX
                ), "Private method not callable."

            if metering is None:
                metering = self.metering

            driver = driver or self.driver
            runtime.rt.env.update({"__Driver": driver})
            clear_random_state()

            install_contract_module_loader(driver=driver)

            balances_key = None
            contract_costs = {}

            try:
                if metering:
                    balances_key = (
                        f"{self.currency_contract}"
                        f"{constants.INDEX_SEPARATOR}"
                        f"{self.balances_hash}"
                        f"{constants.DELIMITER}"
                        f"{sender}"
                    )

                    if self.bypass_balance_amount:
                        balance = 9999999

                    else:
                        balance = self._coerce_balance_value(
                            driver.get(balances_key)
                        )

                    assert balance * chi_cost >= chi, (
                        f"Sender does not have enough chi for the transaction. "
                        f"Balance at key {balances_key} is {balance}"
                    )

                runtime.rt.env.update(environment)
                status_code = 0

                runtime.rt.context._base_state = {
                    "signer": sender,
                    "caller": sender,
                    "this": contract_name,
                    "entry": (contract_name, function_name),
                    "owner": driver.get_owner(contract_name),
                    "submission_name": None,
                }

                if (
                    runtime.rt.context.owner is not None
                    and runtime.rt.context.owner != runtime.rt.context.caller
                ):
                    raise Exception(
                        f"Caller {runtime.rt.context.caller} is not the owner {runtime.rt.context.owner}!"
                    )

                decimal.setcontext(CONTEXT)

                for k, v in kwargs.items():
                    if isinstance(v, float):
                        kwargs[k] = ContractingDecimal(str(v))

                runtime.rt.set_up(stmps=chi * 1000, meter=metering)
                runtime.rt.deduct_transaction_bytes(transaction_size_bytes)
                enable_restricted_imports()
                runtime.rt.begin_contract_metering(contract_name)

                module = import_contract_module(contract_name)
                func = getattr(module, function_name)

                if contract_name == constants.SUBMISSION_CONTRACT_NAME:
                    runtime.rt.context._base_state["submission_name"] = (
                        kwargs.get("name")
                    )

                result = func(**kwargs)
                runtime.rt.deduct_return_value(result)
                transaction_writes = deepcopy(driver.transaction_writes)
                events = deepcopy(driver.log_events)
                runtime.rt.tracer.stop()
                disable_restricted_imports()

                if auto_commit:
                    driver.commit()

            except Exception as e:
                result = e
                status_code = 1
                driver.pending_writes = current_driver_pending_writes
                transaction_writes = {}
                events = []
                if auto_commit:
                    driver.flush_cache()

            finally:
                driver.clear_events()
                driver.clear_transaction_writes()
                runtime.rt.tracer.stop()
                disable_restricted_imports()

            raw_chi_used = runtime.rt.tracer.get_chi_used()
            contract_costs = runtime.rt.finalize_contract_metering(
                fixed_overhead_contract=contract_name,
                fixed_overhead_units=(constants.TRANSACTION_BASE_CHI * 1000),
            )

            chi_used = raw_chi_used // 1000
            chi_used += constants.TRANSACTION_BASE_CHI

            if chi_used > chi:
                chi_used = chi

            if metering:
                assert balances_key is not None, (
                    "Balance key was not set properly. Cannot deduct chi."
                )

                # Use Decimal arithmetic throughout. Previously this went
                # chi_used // chi_cost through Python float ("/"), which
                # loses precision on ratios that aren't exact fractions in
                # base-2 (e.g. chi_used=10000, chi_cost=3). Wrapping the
                # resulting float in ContractingDecimal preserved the
                # imprecise value. Convert to Decimal first so the division
                # itself happens in Decimal space.
                to_deduct = ContractingDecimal(chi_used) / ContractingDecimal(
                    chi_cost
                )

                balance = self._coerce_balance_value(driver.get(balances_key))

                balance = max(balance - to_deduct, 0)

                driver.set(balances_key, balance)
                transaction_writes[balances_key] = balance

                if auto_commit:
                    driver.commit()

            clear_random_state()
            runtime.rt.clean_up()

            output = {
                "status_code": status_code,
                "result": result,
                "chi_used": chi_used,
                "writes": transaction_writes,
                "reads": deepcopy(driver.transaction_reads),
                "prefix_reads": frozenset(driver.transaction_read_prefixes),
                "events": events,
                "contract_costs": contract_costs,
                "error_class": _classify_execution_error(
                    result if status_code != 0 else None
                ),
            }

            disable_restricted_imports()
            return output
