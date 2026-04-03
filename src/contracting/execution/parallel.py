from __future__ import annotations

import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path

from contracting import constants
from contracting.execution import runtime
from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


@dataclass(frozen=True)
class ExecutionRequest:
    sender: str
    contract_name: str
    function_name: str
    kwargs: dict = field(default_factory=dict)
    environment: dict | None = None
    stamps: int = constants.DEFAULT_STAMPS
    stamp_cost: int = constants.STAMPS_PER_T
    metering: bool | None = None
    nonce: int = 0

    def build_kwargs(self) -> dict:
        return deepcopy(self.kwargs)

    def build_environment(self) -> dict | None:
        if self.environment is None:
            return None
        return deepcopy(self.environment)


@dataclass(frozen=True)
class ExecutionAccess:
    index: int
    sender: str
    nonce: int
    reads: frozenset[str]
    prefix_reads: frozenset[str]
    writes: frozenset[str]
    additive_writes: frozenset[str]
    status: int

    @classmethod
    def from_output(
        cls,
        *,
        index: int,
        request: ExecutionRequest,
        output: dict,
    ) -> ExecutionAccess:
        return cls(
            index=index,
            sender=request.sender,
            nonce=request.nonce,
            reads=frozenset(output.get("reads", {}).keys()),
            prefix_reads=frozenset(output.get("prefix_reads", ())),
            writes=frozenset(output.get("writes", {}).keys()),
            additive_writes=frozenset(),
            status=output["status_code"],
        )


@dataclass(frozen=True)
class ParallelStage:
    request_indexes: tuple[int, ...]
    senders: frozenset[str]
    reads: frozenset[str]
    prefix_reads: frozenset[str]
    writes: frozenset[str]
    additive_writes: frozenset[str]

    @property
    def size(self) -> int:
        return len(self.request_indexes)


@dataclass(frozen=True)
class ParallelPlan:
    stages: tuple[ParallelStage, ...]

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    @property
    def max_stage_size(self) -> int:
        if not self.stages:
            return 0
        return max(stage.size for stage in self.stages)

    @property
    def parallelizable_requests(self) -> int:
        return sum(max(stage.size - 1, 0) for stage in self.stages)


class ParallelExecutionPlanner:
    """Build contiguous, deterministic parallel stages."""

    def build(self, accesses: list[ExecutionAccess]) -> ParallelPlan:
        stages: list[ParallelStage] = []
        current_stage: list[ExecutionAccess] = []

        for access in accesses:
            if current_stage and self._conflicts_with_stage(
                access, current_stage
            ):
                stages.append(self._make_stage(current_stage))
                current_stage = [access]
            else:
                current_stage.append(access)

        if current_stage:
            stages.append(self._make_stage(current_stage))

        return ParallelPlan(stages=tuple(stages))

    def _conflicts_with_stage(
        self,
        access: ExecutionAccess,
        stage: list[ExecutionAccess],
    ) -> bool:
        stage_senders = {item.sender for item in stage}
        if access.sender in stage_senders:
            return True

        stage_reads = set().union(*(item.reads for item in stage))
        stage_prefix_reads = set().union(*(item.prefix_reads for item in stage))
        stage_writes = set().union(*(item.writes for item in stage))
        stage_additive_writes = set().union(
            *(item.additive_writes for item in stage)
        )

        if access.writes & stage_writes:
            return True

        if access.writes & stage_reads:
            return True

        if access.writes & stage_additive_writes:
            return True

        if access.reads & stage_writes:
            return True

        if access.reads & stage_additive_writes:
            return True

        if self._prefix_conflicts(access.prefix_reads, stage_writes):
            return True

        if self._prefix_conflicts(access.prefix_reads, stage_additive_writes):
            return True

        if self._prefix_conflicts(stage_prefix_reads, access.writes):
            return True

        if self._prefix_conflicts(stage_prefix_reads, access.additive_writes):
            return True

        if access.additive_writes & stage_reads:
            return True

        if access.additive_writes & stage_writes:
            return True

        return False

    @staticmethod
    def _prefix_conflicts(
        prefixes: set[str] | frozenset[str],
        keys: set[str] | frozenset[str],
    ) -> bool:
        return any(
            key.startswith(prefix) for prefix in prefixes for key in keys
        )

    def _make_stage(self, stage: list[ExecutionAccess]) -> ParallelStage:
        return ParallelStage(
            request_indexes=tuple(item.index for item in stage),
            senders=frozenset(item.sender for item in stage),
            reads=frozenset().union(*(item.reads for item in stage)),
            prefix_reads=frozenset().union(
                *(item.prefix_reads for item in stage)
            ),
            writes=frozenset().union(*(item.writes for item in stage)),
            additive_writes=frozenset().union(
                *(item.additive_writes for item in stage)
            ),
        )


@dataclass
class _WorkerRuntime:
    driver: Driver
    executor: Executor


@dataclass(frozen=True)
class _WorkerConfig:
    storage_home: str
    tracer_mode: str
    metering: bool
    currency_contract: str
    balances_hash: str
    bypass_privates: bool
    bypass_balance_amount: bool


@dataclass(frozen=True)
class _SpeculativeTask:
    config: _WorkerConfig
    request: ExecutionRequest
    base_pending_writes: dict[str, object]


_WORKER_RUNTIMES: dict[_WorkerConfig, _WorkerRuntime] = {}


def _get_worker_runtime(config: _WorkerConfig) -> _WorkerRuntime:
    if runtime.rt.tracer_mode != config.tracer_mode:
        runtime.rt.set_tracer_mode(config.tracer_mode)

    worker_runtime = _WORKER_RUNTIMES.get(config)
    if worker_runtime is not None:
        return worker_runtime

    driver = Driver(
        storage_home=Path(config.storage_home),
        bypass_cache=True,
    )
    executor = Executor(
        driver=driver,
        metering=config.metering,
        currency_contract=config.currency_contract,
        balances_hash=config.balances_hash,
        bypass_privates=config.bypass_privates,
        bypass_balance_amount=config.bypass_balance_amount,
    )
    worker_runtime = _WorkerRuntime(driver=driver, executor=executor)
    _WORKER_RUNTIMES[config] = worker_runtime
    return worker_runtime


def _speculative_execute_request(task: _SpeculativeTask) -> dict:
    worker_runtime = _get_worker_runtime(task.config)
    driver = worker_runtime.driver
    request = task.request

    driver.flush_cache()
    if task.base_pending_writes:
        driver.apply_writes(task.base_pending_writes)

    try:
        return worker_runtime.executor.execute(
            sender=request.sender,
            contract_name=request.contract_name,
            function_name=request.function_name,
            kwargs=request.build_kwargs(),
            environment=request.build_environment(),
            auto_commit=False,
            stamps=request.stamps,
            stamp_cost=request.stamp_cost,
            metering=request.metering,
        )
    finally:
        driver.flush_cache()


@dataclass(frozen=True)
class ParallelExecutionStats:
    parallel_attempted: bool
    worker_count: int
    planned_stage_count: int
    planned_parallelizable_requests: int
    speculative_accepted: int
    serial_fallbacks: int


class ParallelBatchExecutor:
    def __init__(
        self,
        *,
        executor: Executor,
        enabled: bool = True,
        workers: int = 0,
        min_batch_size: int = 8,
        tracer_mode: str | None = None,
    ) -> None:
        self.executor = executor
        self.enabled = enabled
        self.workers = max(int(workers), 0)
        self.min_batch_size = max(int(min_batch_size), 1)
        self.tracer_mode = tracer_mode or runtime.rt.tracer_mode
        self.planner = ParallelExecutionPlanner()
        self._mp_context = multiprocessing.get_context("spawn")
        self._executor: ProcessPoolExecutor | None = None

    def is_enabled_for_batch(self, request_count: int) -> bool:
        return (
            self.enabled
            and self.workers > 0
            and request_count >= self.min_batch_size
        )

    def execute(
        self,
        *,
        requests: list[ExecutionRequest],
        auto_commit: bool = False,
    ) -> tuple[list[dict], ParallelExecutionStats]:
        if not requests:
            return [], self._empty_stats()

        if not self.is_enabled_for_batch(len(requests)):
            return self._execute_serial_batch(
                requests=requests,
                auto_commit=auto_commit,
                parallel_attempted=False,
            )

        base_pending_writes = deepcopy(self.executor.driver.pending_writes)

        try:
            speculative_results = self._speculate_many(
                requests=requests,
                base_pending_writes=base_pending_writes,
            )
        except Exception:
            self.close()
            return self._execute_serial_batch(
                requests=requests,
                auto_commit=auto_commit,
                parallel_attempted=True,
                worker_count=self.workers,
                serial_fallbacks=len(requests),
            )

        accesses = [
            normalized
            for index, (request, result) in enumerate(
                zip(requests, speculative_results, strict=False)
            )
            if (
                normalized := self._normalize_access(
                    index=index,
                    request=request,
                    output=result,
                )
            )
        ]
        plan = self.planner.build(accesses) if accesses else None

        committed_writes: set[str] = set()
        committed_additive_writes: set[str] = set()
        committed_senders: set[str] = set()
        final_results: list[dict] = []
        speculative_accepted = 0
        serial_fallbacks = 0

        for index, request in enumerate(requests):
            result = speculative_results[index]
            access = self._normalize_access(
                index=index,
                request=request,
                output=result,
            )

            if self._should_fallback(
                output=result,
                access=access,
                committed_writes=committed_writes,
                committed_additive_writes=committed_additive_writes,
                committed_senders=committed_senders,
            ):
                result = self._execute_serial_request(request)
                access = self._normalize_access(
                    index=index,
                    request=request,
                    output=result,
                )
                result["speculative_accepted"] = False
                serial_fallbacks += 1
            else:
                self._apply_speculative_output(result)
                result["speculative_accepted"] = True
                speculative_accepted += 1

            result["access"] = access
            final_results.append(result)

            if access is not None:
                committed_writes.update(access.writes)
                committed_additive_writes.update(access.additive_writes)
                committed_senders.add(access.sender)

        if auto_commit:
            self.executor.driver.commit()

        stats = ParallelExecutionStats(
            parallel_attempted=True,
            worker_count=self.workers,
            planned_stage_count=plan.stage_count if plan else 0,
            planned_parallelizable_requests=(
                plan.parallelizable_requests if plan else 0
            ),
            speculative_accepted=speculative_accepted,
            serial_fallbacks=serial_fallbacks,
        )
        return final_results, stats

    def close(self) -> None:
        if self._executor is None:
            return
        self._executor.shutdown(wait=True, cancel_futures=False)
        self._executor = None

    def _empty_stats(self) -> ParallelExecutionStats:
        return ParallelExecutionStats(
            parallel_attempted=False,
            worker_count=0,
            planned_stage_count=0,
            planned_parallelizable_requests=0,
            speculative_accepted=0,
            serial_fallbacks=0,
        )

    def _execute_serial_batch(
        self,
        *,
        requests: list[ExecutionRequest],
        auto_commit: bool,
        parallel_attempted: bool,
        worker_count: int = 0,
        serial_fallbacks: int = 0,
    ) -> tuple[list[dict], ParallelExecutionStats]:
        results = []
        for index, request in enumerate(requests):
            output = self._execute_serial_request(request)
            output["speculative_accepted"] = False
            output["access"] = ExecutionAccess.from_output(
                index=index,
                request=request,
                output=output,
            )
            results.append(output)

        if auto_commit:
            self.executor.driver.commit()

        return results, ParallelExecutionStats(
            parallel_attempted=parallel_attempted,
            worker_count=worker_count,
            planned_stage_count=0,
            planned_parallelizable_requests=0,
            speculative_accepted=0,
            serial_fallbacks=serial_fallbacks,
        )

    def _execute_serial_request(self, request: ExecutionRequest) -> dict:
        return self.executor.execute(
            sender=request.sender,
            contract_name=request.contract_name,
            function_name=request.function_name,
            kwargs=request.build_kwargs(),
            environment=request.build_environment(),
            auto_commit=False,
            stamps=request.stamps,
            stamp_cost=request.stamp_cost,
            metering=request.metering,
        )

    def _speculate_many(
        self,
        *,
        requests: list[ExecutionRequest],
        base_pending_writes: dict[str, object],
    ) -> list[dict]:
        task_template = _WorkerConfig(
            storage_home=str(self.executor.driver.storage_home),
            tracer_mode=self.tracer_mode,
            metering=self.executor.metering,
            currency_contract=self.executor.currency_contract,
            balances_hash=self.executor.balances_hash,
            bypass_privates=self.executor.bypass_privates,
            bypass_balance_amount=self.executor.bypass_balance_amount,
        )
        tasks = [
            _SpeculativeTask(
                config=task_template,
                request=request,
                base_pending_writes=deepcopy(base_pending_writes),
            )
            for request in requests
        ]

        if self.workers == 1:
            return [_speculative_execute_request(task) for task in tasks]

        return list(self._get_executor().map(_speculative_execute_request, tasks))

    def _get_executor(self) -> ProcessPoolExecutor:
        if self._executor is None:
            self._executor = ProcessPoolExecutor(
                max_workers=self.workers,
                mp_context=self._mp_context,
            )
        return self._executor

    @staticmethod
    def _normalize_access(
        *,
        index: int,
        request: ExecutionRequest,
        output: dict | None,
    ) -> ExecutionAccess | None:
        if output is None:
            return None
        return ExecutionAccess.from_output(
            index=index,
            request=request,
            output=output,
        )

    def _apply_speculative_output(self, output: dict) -> None:  # type: ignore[override]
        driver = self.executor.driver
        driver.apply_writes(output.get("writes", {}))
        driver.transaction_reads = deepcopy(output.get("reads", {}))
        driver.transaction_read_prefixes = set(output.get("prefix_reads", ()))
        driver.transaction_writes = deepcopy(output.get("writes", {}))
        driver.log_events = deepcopy(output.get("events", []))

    @staticmethod
    def _should_fallback(
        *,
        output: dict | None,
        access: ExecutionAccess | None,
        committed_writes: set[str],
        committed_additive_writes: set[str],
        committed_senders: set[str],
    ) -> bool:
        if output is None or access is None:
            return True

        if access.sender in committed_senders:
            return True

        if access.reads & committed_writes:
            return True

        if access.reads & committed_additive_writes:
            return True

        if ParallelBatchExecutor._prefix_conflicts(
            access.prefix_reads, committed_writes
        ):
            return True

        if ParallelBatchExecutor._prefix_conflicts(
            access.prefix_reads, committed_additive_writes
        ):
            return True

        if access.writes & committed_writes:
            return True

        if access.writes & committed_additive_writes:
            return True

        if access.additive_writes & committed_writes:
            return True

        return False

    @staticmethod
    def _prefix_conflicts(prefixes: frozenset[str], keys: set[str]) -> bool:
        return any(
            key.startswith(prefix) for prefix in prefixes for key in keys
        )
