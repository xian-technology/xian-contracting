from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import textwrap
import time
from pathlib import Path

from contracting.client import ContractingClient
from contracting.execution.parallel import (
    ExecutionRequest,
    ParallelBatchExecutor,
    ParallelExecutionStats,
)

BENCHMARK_CONTRACT = textwrap.dedent(
    """
    results = Hash()

    @export
    def automate(key: str, rounds: int):
        total = 0
        for i in range(rounds):
            total += (i * 17) % 23
        results[key] = total
        return total
    """
)


def build_client(storage_home: Path, *, tracer_mode: str | None) -> ContractingClient:
    client = ContractingClient(
        storage_home=storage_home,
        tracer_mode=tracer_mode,
    )
    client.submit(BENCHMARK_CONTRACT, name="con_parallel_bench", signer="sys")
    client.raw_driver.commit()
    return client


def build_requests(
    *,
    tx_count: int,
    rounds: int,
    batch_name: str,
) -> list[ExecutionRequest]:
    return [
        ExecutionRequest(
            sender=f"sender_{batch_name}_{index}",
            contract_name="con_parallel_bench",
            function_name="automate",
            kwargs={
                "key": f"{batch_name}_{index}",
                "rounds": rounds,
            },
            nonce=0,
        )
        for index in range(tx_count)
    ]


def execute_batch(
    *,
    client: ContractingClient,
    requests: list[ExecutionRequest],
    workers: int,
    warmup_requests: list[ExecutionRequest] | None = None,
) -> tuple[list[dict], ParallelExecutionStats, float]:
    executor = ParallelBatchExecutor(
        executor=client.executor,
        enabled=workers > 0,
        workers=workers,
        min_batch_size=1,
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

    for request in requests:
        key = request.kwargs["key"]
        storage_key = f"con_parallel_bench.results:{key}"
        serial_value = serial_client.raw_driver.get(storage_key)
        parallel_value = parallel_client.raw_driver.get(storage_key)
        if serial_value != parallel_value:
            raise AssertionError(
                f"State mismatch for {storage_key}: {serial_value!r} != {parallel_value!r}"
            )


def benchmark_iteration(
    *,
    tx_count: int,
    rounds: int,
    workers: int,
    tracer_mode: str | None,
    warmup_transactions: int,
    iteration_index: int,
) -> dict:
    batch_name = f"bench_{iteration_index}"
    warmup_name = f"warmup_{iteration_index}"
    requests = build_requests(
        tx_count=tx_count,
        rounds=rounds,
        batch_name=batch_name,
    )
    warmup_requests = build_requests(
        tx_count=max(2, min(tx_count, warmup_transactions)),
        rounds=rounds,
        batch_name=warmup_name,
    )

    with (
        tempfile.TemporaryDirectory() as serial_dir,
        tempfile.TemporaryDirectory() as parallel_dir,
    ):
        serial_client = build_client(
            Path(serial_dir) / "xian",
            tracer_mode=tracer_mode,
        )
        parallel_client = build_client(
            Path(parallel_dir) / "xian",
            tracer_mode=tracer_mode,
        )

        serial_outputs, serial_stats, serial_duration = execute_batch(
            client=serial_client,
            requests=requests,
            workers=0,
        )
        parallel_outputs, parallel_stats, parallel_duration = execute_batch(
            client=parallel_client,
            requests=requests,
            workers=workers,
            warmup_requests=warmup_requests,
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
            "serial_prefiltered": parallel_stats.serial_prefiltered,
            "serial_fallbacks": parallel_stats.serial_fallbacks,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark non-conflicting contract execution throughput with "
            "parallel speculation disabled and enabled."
        )
    )
    parser.add_argument("--tx-count", type=int, default=256)
    parser.add_argument("--rounds", type=int, default=50_000)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument(
        "--workers",
        type=int,
        default=min(os.cpu_count() or 1, 8),
    )
    parser.add_argument("--warmup-transactions", type=int, default=16)
    parser.add_argument("--tracer-mode", default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")

    print(
        "Benchmarking non-conflicting contract transactions with unique "
        "senders and keys."
    )
    print(
        json.dumps(
            {
                "tx_count": args.tx_count,
                "rounds": args.rounds,
                "iterations": args.iterations,
                "workers": args.workers,
                "warmup_transactions": args.warmup_transactions,
                "tracer_mode": args.tracer_mode,
            },
            sort_keys=True,
        )
    )

    samples = [
        benchmark_iteration(
            tx_count=args.tx_count,
            rounds=args.rounds,
            workers=args.workers,
            tracer_mode=args.tracer_mode,
            warmup_transactions=args.warmup_transactions,
            iteration_index=index,
        )
        for index in range(1, args.iterations + 1)
    ]

    for sample in samples:
        print(
            "iteration {iteration}: serial={serial_tps:.2f} TPS "
            "({serial_duration_s:.3f}s), parallel={parallel_tps:.2f} TPS "
            "({parallel_duration_s:.3f}s), speedup={speedup:.2f}x, "
            "accepted={accepted}/{tx_count}, waves={waves}, "
            "prefiltered={prefiltered}, fallbacks={fallbacks}".format(
                iteration=sample["iteration"],
                serial_tps=sample["serial_tps"],
                serial_duration_s=sample["serial_duration_s"],
                parallel_tps=sample["parallel_tps"],
                parallel_duration_s=sample["parallel_duration_s"],
                speedup=sample["speedup"],
                accepted=sample["parallel_stats"]["speculative_accepted"],
                tx_count=args.tx_count,
                waves=sample["parallel_stats"]["speculative_wave_count"],
                prefiltered=sample["parallel_stats"]["serial_prefiltered"],
                fallbacks=sample["parallel_stats"]["serial_fallbacks"],
            )
        )

    serial_tps = [sample["serial_tps"] for sample in samples]
    parallel_tps = [sample["parallel_tps"] for sample in samples]
    speedups = [sample["speedup"] for sample in samples]

    summary = {
        "tx_count": args.tx_count,
        "rounds": args.rounds,
        "iterations": args.iterations,
        "workers": args.workers,
        "serial_tps_mean": statistics.mean(serial_tps),
        "serial_tps_median": statistics.median(serial_tps),
        "parallel_tps_mean": statistics.mean(parallel_tps),
        "parallel_tps_median": statistics.median(parallel_tps),
        "speedup_mean": statistics.mean(speedups),
        "speedup_median": statistics.median(speedups),
        "parallel_stats_last": samples[-1]["parallel_stats"],
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
