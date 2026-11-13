"""Local transaction adapter for the canonical native VM."""

from xian_runtime_types.time import Datetime

from contracting import constants
from contracting.execution.errors import classify_execution_error
from contracting.execution.runtime import rt


def _execution_context(*, sender, contract_name, function_name, kwargs, environment):
    context = dict(environment or {})
    if context.get("now") is None:
        context["now"] = Datetime(1970, 1, 1)
    context.update(
        signer=sender,
        caller=sender,
        this=contract_name,
        entry=(contract_name, function_name),
        submission_name=kwargs.get("name") if contract_name == "submission" else None,
    )
    return context


class NativeExecutor:
    def __init__(self, driver, *, metering):
        self.driver = driver
        self.metering = metering

    def execute(
        self,
        *,
        sender,
        contract_name,
        function_name,
        kwargs,
        environment=None,
        chi=constants.DEFAULT_CHI,
        metering=None,
        auto_commit=False,
        driver=None,
        transaction_size_bytes=0,
        chi_cost=constants.CHI_PER_T,
    ):
        from xian_vm_core import NativeExecutionResult, execute_contract

        driver = self.driver if driver is None else driver
        context = _execution_context(
            sender=sender,
            contract_name=contract_name,
            function_name=function_name,
            kwargs=kwargs,
            environment=environment,
        )
        # The Python host bridge installs transaction context for the native VM.
        with rt.execution_lock:
            driver.clear_transaction_reads()
            context["owner"] = driver.get_owner(contract_name)
            try:
                result = execute_contract(
                    driver=driver,
                    contract_name=contract_name,
                    function_name=function_name,
                    context=context,
                    kwargs=kwargs,
                    meter=self.metering if metering is None else metering,
                    chi_budget_raw=max(int(chi), 0) * 1000,
                    transaction_size_bytes=max(int(transaction_size_bytes), 0),
                    vm_profile=driver.vm_profile,
                )
            except Exception as exc:
                # Argument conversion and the host bridge can fail before VM entry.
                result = NativeExecutionResult(
                    status_code=1,
                    result=exc,
                    writes={},
                    events=[],
                    snapshots=[],
                    raw_cost=0,
                    chi_used=0,
                    contract_costs={},
                )
            reads, prefix_reads = driver.transaction_access()
            error = None
            if result.status_code:
                error = (
                    result.result
                    if isinstance(result.result, Exception)
                    else RuntimeError(str(result.result))
                )
            else:
                driver.apply_writes(result.writes)
                if auto_commit:
                    driver.commit()
            return {
                "status_code": result.status_code,
                "result": error if error else result.result,
                "writes": result.writes,
                "chi_used": result.chi_used,
                "events": result.events,
                "reads": reads,
                "prefix_reads": prefix_reads,
                "contract_costs": result.contract_costs,
                "error_class": classify_execution_error(error),
            }
