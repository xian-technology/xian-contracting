import tempfile
import textwrap
import unittest
from pathlib import Path

from contracting.client import ContractingClient
from contracting.execution.parallel import (
    ExecutionRequest,
    ParallelBatchExecutor,
)

CONTRACT_CODE = textwrap.dedent(
    """
    metadata = Hash()

    @export
    def change_metadata(key: str, value: str):
        metadata[key] = value
        return metadata[key]
    """
)


SCAN_CONTRACT_CODE = textwrap.dedent(
    """
    values = Hash(default_value=0)
    out = Variable()

    @construct
    def seed():
        values['a'] = 1
        out.set(0)

    @export
    def add_value(key: str, amount: int):
        values[key] = amount

    @export
    def snapshot_sum():
        out.set(sum(values.all()))
        return out.get()
    """
)


COUNTER_CONTRACT_CODE = textwrap.dedent(
    """
    value = Variable()

    @construct
    def seed():
        value.set(0)

    @export
    def increment():
        current = value.get()
        value.set(current + 1)
        return value.get()
    """
)


READ_WRITE_CONTRACT_CODE = textwrap.dedent(
    """
    value = Variable()

    @construct
    def seed():
        value.set(0)

    @export
    def set_value(new_value: int):
        value.set(new_value)
        return value.get()

    @export
    def get_value():
        return value.get()
    """
)


class TestParallelBatchExecutor(unittest.TestCase):
    def _build_client(self, storage_home: Path) -> ContractingClient:
        client = ContractingClient(storage_home=storage_home)
        client.submit(CONTRACT_CODE, name="con_token_a", signer="sys")
        client.submit(CONTRACT_CODE, name="con_token_b", signer="bob")
        client.submit(SCAN_CONTRACT_CODE, name="con_scan", signer="sys")
        client.submit(COUNTER_CONTRACT_CODE, name="con_counter", signer="sys")
        client.submit(READ_WRITE_CONTRACT_CODE, name="con_rw", signer="sys")
        client.raw_driver.commit()
        return client

    def test_parallel_batch_matches_serial_with_same_sender_prefilter(self):
        requests = [
            ExecutionRequest(
                sender="sys",
                contract_name="con_token_a",
                function_name="change_metadata",
                kwargs={"key": "alpha", "value": "one"},
                nonce=0,
            ),
            ExecutionRequest(
                sender="bob",
                contract_name="con_token_b",
                function_name="change_metadata",
                kwargs={"key": "beta", "value": "two"},
                nonce=0,
            ),
            ExecutionRequest(
                sender="sys",
                contract_name="con_token_a",
                function_name="change_metadata",
                kwargs={"key": "alpha", "value": "three"},
                nonce=1,
            ),
        ]

        with (
            tempfile.TemporaryDirectory() as serial_dir,
            tempfile.TemporaryDirectory() as parallel_dir,
        ):
            serial_client = self._build_client(Path(serial_dir) / "xian")
            parallel_client = self._build_client(Path(parallel_dir) / "xian")

            serial_outputs = [
                serial_client.executor.execute(
                    sender=request.sender,
                    contract_name=request.contract_name,
                    function_name=request.function_name,
                    kwargs=request.build_kwargs(),
                    environment=request.build_environment(),
                    stamps=request.stamps,
                    stamp_cost=request.stamp_cost,
                    metering=request.metering,
                )
                for request in requests
            ]

            parallel_executor = ParallelBatchExecutor(
                executor=parallel_client.executor,
                enabled=True,
                workers=1,
                min_batch_size=1,
            )
            parallel_outputs, stats = parallel_executor.execute(
                requests=requests
            )

            self.assertEqual(stats.speculative_accepted, 2)
            self.assertEqual(stats.serial_prefiltered, 1)
            self.assertEqual(stats.serial_fallbacks, 0)
            self.assertEqual(
                [output["result"] for output in parallel_outputs],
                [output["result"] for output in serial_outputs],
            )
            self.assertEqual(
                parallel_client.raw_driver.get("con_token_a.metadata:alpha"),
                serial_client.raw_driver.get("con_token_a.metadata:alpha"),
            )
            self.assertEqual(
                parallel_client.raw_driver.get("con_token_b.metadata:beta"),
                serial_client.raw_driver.get("con_token_b.metadata:beta"),
            )

    def test_parallel_batch_defers_prefix_reads_without_serial_fallback(self):
        requests = [
            ExecutionRequest(
                sender="alice",
                contract_name="con_scan",
                function_name="add_value",
                kwargs={"key": "b", "amount": 5},
                nonce=0,
            ),
            ExecutionRequest(
                sender="bob",
                contract_name="con_scan",
                function_name="snapshot_sum",
                kwargs={},
                nonce=0,
            ),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            client = self._build_client(Path(temp_dir) / "xian")
            executor = ParallelBatchExecutor(
                executor=client.executor,
                enabled=True,
                workers=1,
                min_batch_size=1,
            )

            outputs, stats = executor.execute(requests=requests)

            self.assertEqual(stats.speculative_accepted, 1)
            self.assertEqual(stats.serial_prefiltered, 1)
            self.assertEqual(stats.serial_fallbacks, 0)
            self.assertEqual(
                outputs[1]["prefix_reads"],
                frozenset({"con_scan.values:"}),
            )
            self.assertEqual(client.raw_driver.get("con_scan.out"), 6)

    def test_parallel_batch_sees_base_pending_writes(self):
        requests = [
            ExecutionRequest(
                sender="alice",
                contract_name="con_counter",
                function_name="increment",
                kwargs={},
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            client = self._build_client(Path(temp_dir) / "xian")
            client.raw_driver.set("con_counter.value", 10)

            executor = ParallelBatchExecutor(
                executor=client.executor,
                enabled=True,
                workers=1,
                min_batch_size=1,
            )
            outputs, stats = executor.execute(requests=requests)

            self.assertFalse(outputs[0]["speculative_accepted"])
            self.assertEqual(outputs[0]["result"], 11)
            self.assertEqual(stats.speculative_accepted, 0)
            self.assertEqual(stats.serial_prefiltered, 1)
            self.assertEqual(client.raw_driver.get("con_counter.value"), 11)

    def test_parallel_batch_respeculates_conflict_tail(self):
        requests = [
            ExecutionRequest(
                sender="alice",
                contract_name="con_rw",
                function_name="set_value",
                kwargs={"new_value": 7},
                nonce=0,
            ),
            ExecutionRequest(
                sender="bob",
                contract_name="con_rw",
                function_name="get_value",
                kwargs={},
                nonce=0,
            ),
            ExecutionRequest(
                sender="carol",
                contract_name="con_token_b",
                function_name="change_metadata",
                kwargs={"key": "gamma", "value": "three"},
                nonce=0,
            ),
        ]

        with (
            tempfile.TemporaryDirectory() as serial_dir,
            tempfile.TemporaryDirectory() as parallel_dir,
        ):
            serial_client = self._build_client(Path(serial_dir) / "xian")
            parallel_client = self._build_client(Path(parallel_dir) / "xian")

            serial_outputs = [
                serial_client.executor.execute(
                    sender=request.sender,
                    contract_name=request.contract_name,
                    function_name=request.function_name,
                    kwargs=request.build_kwargs(),
                    environment=request.build_environment(),
                    stamps=request.stamps,
                    stamp_cost=request.stamp_cost,
                    metering=request.metering,
                )
                for request in requests
            ]

            parallel_executor = ParallelBatchExecutor(
                executor=parallel_client.executor,
                enabled=True,
                workers=1,
                min_batch_size=1,
            )
            parallel_outputs, stats = parallel_executor.execute(
                requests=requests
            )

            self.assertEqual(stats.speculative_wave_count, 2)
            self.assertEqual(stats.speculative_accepted, 3)
            self.assertEqual(stats.serial_prefiltered, 0)
            self.assertEqual(stats.serial_fallbacks, 0)
            self.assertEqual(
                [output["result"] for output in parallel_outputs],
                [output["result"] for output in serial_outputs],
            )
            self.assertEqual(parallel_client.raw_driver.get("con_rw.value"), 7)
            self.assertEqual(
                parallel_client.raw_driver.get("con_token_b.metadata:gamma"),
                "three",
            )


if __name__ == "__main__":
    unittest.main()
