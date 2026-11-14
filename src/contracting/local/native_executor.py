"""Local transaction adapter for the canonical native VM.

A call runs in Rust with the code a block runs (``xian_vm_core.execute_tx``)
over the driver's LMDB environment and pending state, without fees; a
success's writes are staged in the driver as a block stages them.
"""

from xian_runtime_types.time import Datetime

from contracting import constants
from contracting.execution.errors import classify_execution_error
from contracting.runtime_features import RUNTIME_FEATURE_ZK, runtime_feature_without_state


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


def _failure(result):
    """The exception a failed call raises (its text when it has no type)."""
    return result if isinstance(result, Exception) else RuntimeError(str(result))


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
        from xian_vm_core import execute_tx

        driver = self.driver if driver is None else driver
        context = _execution_context(
            sender=sender,
            contract_name=contract_name,
            function_name=function_name,
            kwargs=kwargs,
            environment=environment,
        )
        storage, pending = driver.committed_storage()
        run = execute_tx(
            storage,
            pending,
            sender=sender,
            contract_name=contract_name,
            function_name=function_name,
            kwargs=kwargs,
            context=context,
            meter=self.metering if metering is None else metering,
            chi_budget=max(int(chi), 0),
            transaction_size_bytes=max(int(transaction_size_bytes), 0),
            zk_enabled_without_state=runtime_feature_without_state(driver, RUNTIME_FEATURE_ZK),
        )
        output = {
            "status_code": run.status_code,
            "result": _failure(run.result) if run.status_code else run.result,
            "writes": run.writes,
            "chi_used": run.chi_used,
            "events": run.events,
            "contract_costs": run.contract_costs,
        }
        if output["status_code"] == 0 and auto_commit:
            driver.commit()
        error = output["result"] if output["status_code"] else None
        return {**output, "error_class": classify_execution_error(error)}
