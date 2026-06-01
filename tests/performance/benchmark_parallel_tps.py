from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

from contracting.execution.parallel import (
    ExecutionRequest,
    ParallelBatchExecutor,
    ParallelExecutionStats,
)
from contracting.local import ContractingClient

BENCHMARK_CONTRACT = textwrap.dedent(
    """
    results = Hash()
    values = Hash(default_value=0)
    counter = Variable()

    @construct
    def seed():
        counter.set(0)

    def work(rounds: int):
        total = 0
        for i in range(rounds):
            total += (i * 17) % 23
        return total

    @export
    def automate(key: str, rounds: int):
        total = work(rounds)
        results[key] = total
        return total

    @export
    def set_value(key: str, amount: int, rounds: int):
        total = work(rounds)
        values[key] = amount + total
        return values[key]

    @export
    def snapshot_sum(key: str, rounds: int):
        total = work(rounds)
        result = sum(values.all()) + total
        results[key] = result
        return result

    @export
    def increment(key: str, rounds: int):
        total = work(rounds)
        current = counter.get()
        counter.set(current + 1)
        results[key] = current + total
        return counter.get()
    """
)


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    tx_count: int
    rounds: int


SCENARIOS = {
    "independent_cpu": Scenario(
        name="independent_cpu",
        description="Unique senders write unique keys with CPU-heavy contract work.",
        tx_count=256,
        rounds=50_000,
    ),
    "independent_light": Scenario(
        name="independent_light",
        description="Unique senders write unique keys with light contract work.",
        tx_count=256,
        rounds=1_000,
    ),
    "small_block": Scenario(
        name="small_block",
        description="Small non-conflicting block near the default activation threshold.",
        tx_count=8,
        rounds=10_000,
    ),
    "same_sender": Scenario(
        name="same_sender",
        description="One sender submits otherwise independent transactions.",
        tx_count=128,
        rounds=10_000,
    ),
    "hot_counter": Scenario(
        name="hot_counter",
        description="Unique senders all contend on one counter variable.",
        tx_count=128,
        rounds=10_000,
    ),
    "prefix_scan_tail": Scenario(
        name="prefix_scan_tail",
        description="Many independent writes followed by one Hash.all() prefix scan.",
        tx_count=128,
        rounds=10_000,
    ),
    "alternating_prefix_scans": Scenario(
        name="alternating_prefix_scans",
        description="Alternating writes and Hash.all() scans create repeated prefix conflicts.",
        tx_count=64,
        rounds=5_000,
    ),
    "mixed_80_20": Scenario(
        name="mixed_80_20",
        description="Mostly independent writes with periodic hot-counter conflicts.",
        tx_count=128,
        rounds=10_000,
    ),
}


def build_client(storage_home: Path) -> ContractingClient:
    client = ContractingClient(storage_home=storage_home)
    client.submit(BENCHMARK_CONTRACT, name="con_parallel_bench", signer="sys")
    client.raw_driver.commit()
    return client


def build_requests(
    *,
    scenario: str,
    tx_count: int,
    rounds: int,
    batch_name: str,
) -> list[ExecutionRequest]:
    nonce_by_sender: dict[str, int] = {}

    def next_nonce(sender: str) -> int:
        nonce = nonce_by_sender.get(sender, 0)
        nonce_by_sender[sender] = nonce + 1
        return nonce

    def request(
        *,
        index: int,
        sender: str,
        function_name: str,
        kwargs: dict,
    ) -> ExecutionRequest:
        return ExecutionRequest(
            sender=sender,
            contract_name="con_parallel_bench",
            function_name=function_name,
            kwargs=kwargs,
            nonce=next_nonce(sender),
        )

    requests: list[ExecutionRequest] = []
    for index in range(tx_count):
        sender = f"sender_{batch_name}_{index}"
        key = f"{batch_name}_{index}"

        if scenario in {"independent_cpu", "independent_light", "small_block"}:
            requests.append(
                request(
                    index=index,
                    sender=sender,
                    function_name="automate",
                    kwargs={"key": key, "rounds": rounds},
                )
            )
            continue

        if scenario == "same_sender":
            requests.append(
                request(
                    index=index,
                    sender=f"sender_{batch_name}_shared",
                    function_name="automate",
                    kwargs={"key": key, "rounds": rounds},
                )
            )
            continue

        if scenario == "hot_counter":
            requests.append(
                request(
                    index=index,
                    sender=sender,
                    function_name="increment",
                    kwargs={"key": key, "rounds": rounds},
                )
            )
            continue

        if scenario == "prefix_scan_tail":
            if index == tx_count - 1:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="snapshot_sum",
                        kwargs={"key": key, "rounds": rounds},
                    )
                )
            else:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="set_value",
                        kwargs={"key": key, "amount": index, "rounds": rounds},
                    )
                )
            continue

        if scenario == "alternating_prefix_scans":
            if index % 2:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="snapshot_sum",
                        kwargs={"key": key, "rounds": rounds},
                    )
                )
            else:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="set_value",
                        kwargs={"key": key, "amount": index, "rounds": rounds},
                    )
                )
            continue

        if scenario == "mixed_80_20":
            if index % 5 == 4:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="increment",
                        kwargs={"key": key, "rounds": rounds},
                    )
                )
            else:
                requests.append(
                    request(
                        index=index,
                        sender=sender,
                        function_name="automate",
                        kwargs={"key": key, "rounds": rounds},
                    )
                )
            continue

        raise ValueError(f"Unknown scenario: {scenario}")

    return requests


def execute_batch(
    *,
    client: ContractingClient,
    requests: list[ExecutionRequest],
    workers: int,
    warmup_requests: list[ExecutionRequest] | None = None,
    max_speculative_waves: int,
    min_wave_acceptance_ratio: float,
    low_acceptance_min_wave_size: int,
) -> tuple[list[dict], ParallelExecutionStats, float]:
    executor = ParallelBatchExecutor(
        executor=client.executor,
        enabled=workers > 0,
        workers=workers,
        min_batch_size=1,
        max_speculative_waves=max_speculative_waves,
        min_wave_acceptance_ratio=min_wave_acceptance_ratio,
        low_acceptance_min_wave_size=low_acceptance_min_wave_size,
    )

    try:
        if warmup_requests:
            executor.execute(requests=warmup_requests)

        start = time.perf_counter()
        outputs, stats = executor.execute(requests=requests)
        duration = time.perf_counter() - start
        return outputs, stats, duration
    finally:
        executor.close()


def assert_equivalent_results(
    *,
    requests: list[ExecutionRequest],
    serial_outputs: list[dict],
    parallel_outputs: list[dict],
    serial_client: ContractingClient,
    parallel_client: ContractingClient,
) -> None:
    if len(serial_outputs) != len(parallel_outputs):
        raise AssertionError("Serial and parallel output lengths differ")

    serial_results = [output["result"] for output in serial_outputs]
    parallel_results = [output["result"] for output in parallel_outputs]
    if serial_results != parallel_results:
        raise AssertionError("Serial and parallel result payloads differ")

    serial_statuses = [output["status_code"] for output in serial_outputs]
    parallel_statuses = [output["status_code"] for output in parallel_outputs]
    if serial_statuses != parallel_statuses:
        raise AssertionError("Serial and parallel status codes differ")

    state_prefixes = (
        "con_parallel_bench.results",
        "con_parallel_bench.values",
        "con_parallel_bench.counter",
    )
    serial_state = {}
    parallel_state = {}
    for prefix in state_prefixes:
        serial_state.update(serial_client.raw_driver.items(prefix))
        parallel_state.update(parallel_client.raw_driver.items(prefix))
    if serial_state != parallel_state:
        raise AssertionError("Serial and parallel benchmark state differs")


def benchmark_iteration(
    *,
    scenario: str,
    tx_count: int,
    rounds: int,
    workers: int,
    warmup_transactions: int,
    iteration_index: int,
    max_speculative_waves: int,
    min_wave_acceptance_ratio: float,
    low_acceptance_min_wave_size: int,
) -> dict:
    batch_name = f"bench_{iteration_index}"
    warmup_name = f"warmup_{iteration_index}"
    requests = build_requests(
        scenario=scenario,
        tx_count=tx_count,
        rounds=rounds,
        batch_name=batch_name,
    )
    warmup_requests = build_requests(
        scenario=scenario,
        tx_count=max(2, min(tx_count, warmup_transactions)),
        rounds=rounds,
        batch_name=warmup_name,
    )

    with (
        tempfile.TemporaryDirectory() as serial_dir,
        tempfile.TemporaryDirectory() as parallel_dir,
    ):
        serial_client = build_client(Path(serial_dir) / "xian")
        parallel_client = build_client(Path(parallel_dir) / "xian")

        serial_outputs, serial_stats, serial_duration = execute_batch(
            client=serial_client,
            requests=requests,
            workers=0,
            warmup_requests=warmup_requests,
            max_speculative_waves=max_speculative_waves,
            min_wave_acceptance_ratio=min_wave_acceptance_ratio,
            low_acceptance_min_wave_size=low_acceptance_min_wave_size,
        )
        parallel_outputs, parallel_stats, parallel_duration = execute_batch(
            client=parallel_client,
            requests=requests,
            workers=workers,
            warmup_requests=warmup_requests,
            max_speculative_waves=max_speculative_waves,
            min_wave_acceptance_ratio=min_wave_acceptance_ratio,
            low_acceptance_min_wave_size=low_acceptance_min_wave_size,
        )

        assert_equivalent_results(
            requests=requests,
            serial_outputs=serial_outputs,
            parallel_outputs=parallel_outputs,
            serial_client=serial_client,
            parallel_client=parallel_client,
        )

    serial_tps = tx_count / serial_duration
    parallel_tps = tx_count / parallel_duration
    return {
        "scenario": scenario,
        "iteration": iteration_index,
        "serial_duration_s": serial_duration,
        "parallel_duration_s": parallel_duration,
        "serial_tps": serial_tps,
        "parallel_tps": parallel_tps,
        "speedup": parallel_tps / serial_tps,
        "serial_stats": {
            "parallel_attempted": serial_stats.parallel_attempted,
            "serial_fallbacks": serial_stats.serial_fallbacks,
        },
        "parallel_stats": {
            "worker_count": parallel_stats.worker_count,
            "planned_stage_count": parallel_stats.planned_stage_count,
            "planned_parallelizable_requests": (
                parallel_stats.planned_parallelizable_requests
            ),
            "speculative_wave_count": parallel_stats.speculative_wave_count,
            "speculative_accepted": parallel_stats.speculative_accepted,
            "speculative_rejected": parallel_stats.speculative_rejected,
            "serial_prefiltered": parallel_stats.serial_prefiltered,
            "serial_fallbacks": parallel_stats.serial_fallbacks,
            "guardrail_fallbacks": parallel_stats.guardrail_fallbacks,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark non-conflicting contract execution throughput with "
            "parallel speculation disabled and enabled."
        )
    )
    parser.add_argument(
        "--scenario",
        choices=[*SCENARIOS.keys(), "all"],
        default="independent_cpu",
    )
    parser.add_argument("--tx-count", type=int)
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument(
        "--workers",
        type=int,
        default=min(os.cpu_count() or 1, 8),
    )
    parser.add_argument("--warmup-transactions", type=int, default=16)
    parser.add_argument("--max-speculative-waves", type=int, default=4)
    parser.add_argument("--min-wave-acceptance-ratio", type=float, default=0.25)
    parser.add_argument("--low-acceptance-min-wave-size", type=int, default=8)
    parser.add_argument("--markdown", action="store_true")
    return parser.parse_args()


def run_scenario(args: argparse.Namespace, scenario: Scenario) -> dict:
    tx_count = args.tx_count if args.tx_count is not None else scenario.tx_count
    rounds = args.rounds if args.rounds is not None else scenario.rounds

    print(
        f"Benchmarking {scenario.name}: {scenario.description}"
    )
    print(
        json.dumps(
            {
                "scenario": scenario.name,
                "tx_count": tx_count,
                "rounds": rounds,
                "iterations": args.iterations,
                "workers": args.workers,
                "warmup_transactions": args.warmup_transactions,
                "max_speculative_waves": args.max_speculative_waves,
                "min_wave_acceptance_ratio": args.min_wave_acceptance_ratio,
                "low_acceptance_min_wave_size": args.low_acceptance_min_wave_size,
            },
            sort_keys=True,
        )
    )

    samples = [
        benchmark_iteration(
            scenario=scenario.name,
            tx_count=tx_count,
            rounds=rounds,
            workers=args.workers,
            warmup_transactions=args.warmup_transactions,
            iteration_index=index,
            max_speculative_waves=args.max_speculative_waves,
            min_wave_acceptance_ratio=args.min_wave_acceptance_ratio,
            low_acceptance_min_wave_size=args.low_acceptance_min_wave_size,
        )
        for index in range(1, args.iterations + 1)
    ]

    for sample in samples:
        print(
            "{scenario} "
            "iteration {iteration}: serial={serial_tps:.2f} TPS "
            "({serial_duration_s:.3f}s), parallel={parallel_tps:.2f} TPS "
            "({parallel_duration_s:.3f}s), speedup={speedup:.2f}x, "
            "accepted={accepted}/{tx_count}, rejected={rejected}, waves={waves}, "
            "prefiltered={prefiltered}, fallbacks={fallbacks}, "
            "guardrail={guardrail}".format(
                scenario=scenario.name,
                iteration=sample["iteration"],
                serial_tps=sample["serial_tps"],
                serial_duration_s=sample["serial_duration_s"],
                parallel_tps=sample["parallel_tps"],
                parallel_duration_s=sample["parallel_duration_s"],
                speedup=sample["speedup"],
                accepted=sample["parallel_stats"]["speculative_accepted"],
                rejected=sample["parallel_stats"]["speculative_rejected"],
                tx_count=tx_count,
                waves=sample["parallel_stats"]["speculative_wave_count"],
                prefiltered=sample["parallel_stats"]["serial_prefiltered"],
                fallbacks=sample["parallel_stats"]["serial_fallbacks"],
                guardrail=sample["parallel_stats"]["guardrail_fallbacks"],
            )
        )

    serial_tps = [sample["serial_tps"] for sample in samples]
    parallel_tps = [sample["parallel_tps"] for sample in samples]
    speedups = [sample["speedup"] for sample in samples]
    last_stats = samples[-1]["parallel_stats"]

    summary = {
        "scenario": scenario.name,
        "description": scenario.description,
        "tx_count": tx_count,
        "rounds": rounds,
        "iterations": args.iterations,
        "workers": args.workers,
        "serial_tps_mean": statistics.mean(serial_tps),
        "serial_tps_median": statistics.median(serial_tps),
        "parallel_tps_mean": statistics.mean(parallel_tps),
        "parallel_tps_median": statistics.median(parallel_tps),
        "speedup_mean": statistics.mean(speedups),
        "speedup_median": statistics.median(speedups),
        "parallel_acceptance_ratio_last": (
            last_stats["speculative_accepted"] / tx_count if tx_count else 0.0
        ),
        "parallel_stats_last": last_stats,
    }
    print(json.dumps(summary, sort_keys=True))
    return summary


def print_markdown_table(summaries: list[dict]) -> None:
    print()
    print("| Scenario | Tx | Rounds | Serial TPS | Parallel TPS | Speedup | Accepted | Fallbacks |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    for summary in summaries:
        stats = summary["parallel_stats_last"]
        print(
            "| {scenario} | {tx_count} | {rounds} | {serial:.0f} | {parallel:.0f} | "
            "{speedup:.2f}x | {accepted}/{tx_count} | {fallbacks} |".format(
                scenario=summary["scenario"],
                tx_count=summary["tx_count"],
                rounds=summary["rounds"],
                serial=summary["serial_tps_median"],
                parallel=summary["parallel_tps_median"],
                speedup=summary["speedup_median"],
                accepted=stats["speculative_accepted"],
                fallbacks=stats["serial_fallbacks"] + stats["serial_prefiltered"],
            )
        )


def main() -> int:
    args = parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")

    scenario_names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    summaries = [run_scenario(args, SCENARIOS[name]) for name in scenario_names]
    if args.markdown:
        print_markdown_table(summaries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
