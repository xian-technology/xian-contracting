import unittest

from contracting.execution.parallel import (
    ExecutionAccess,
    ParallelExecutionPlanner,
)


def access(
    index,
    sender,
    reads=(),
    prefix_reads=(),
    writes=(),
    additive_writes=(),
    nonce=0,
    status=0,
):
    return ExecutionAccess(
        index=index,
        sender=sender,
        nonce=nonce,
        reads=frozenset(reads),
        prefix_reads=frozenset(prefix_reads),
        writes=frozenset(writes),
        additive_writes=frozenset(additive_writes),
        status=status,
    )


class TestParallelExecutionPlanner(unittest.TestCase):
    def setUp(self):
        self.planner = ParallelExecutionPlanner()

    def test_groups_independent_requests_into_one_stage(self):
        plan = self.planner.build(
            [
                access(0, "alice", reads={"currency.balances:alice"}),
                access(1, "bob", reads={"currency.balances:bob"}),
                access(2, "carol", writes={"dex.orders:1"}),
            ]
        )

        self.assertEqual(plan.stage_count, 1)
        self.assertEqual(plan.max_stage_size, 3)
        self.assertEqual(plan.parallelizable_requests, 2)
        self.assertEqual(plan.stages[0].request_indexes, (0, 1, 2))

    def test_splits_stage_on_write_read_conflict(self):
        plan = self.planner.build(
            [
                access(0, "alice", writes={"currency.balances:alice"}),
                access(1, "bob", reads={"currency.balances:alice"}),
                access(2, "carol", reads={"currency.balances:carol"}),
            ]
        )

        self.assertEqual(plan.stage_count, 2)
        self.assertEqual(plan.stages[0].request_indexes, (0,))
        self.assertEqual(plan.stages[1].request_indexes, (1, 2))

    def test_splits_stage_on_same_sender(self):
        plan = self.planner.build(
            [
                access(0, "alice", writes={"currency.balances:alice"}, nonce=1),
                access(1, "alice", writes={"dex.orders:1"}, nonce=2),
            ]
        )

        self.assertEqual(plan.stage_count, 2)
        self.assertEqual(plan.stages[0].request_indexes, (0,))
        self.assertEqual(plan.stages[1].request_indexes, (1,))

    def test_splits_stage_on_prefix_scan_after_write(self):
        plan = self.planner.build(
            [
                access(0, "alice", writes={"con_scan.values:b"}),
                access(1, "bob", prefix_reads={"con_scan.values:"}),
            ]
        )

        self.assertEqual(plan.stage_count, 2)
        self.assertEqual(plan.stages[0].request_indexes, (0,))
        self.assertEqual(plan.stages[1].request_indexes, (1,))

    def test_splits_stage_on_write_after_prefix_scan(self):
        plan = self.planner.build(
            [
                access(0, "alice", prefix_reads={"con_scan.values:"}),
                access(1, "bob", writes={"con_scan.values:b"}),
            ]
        )

        self.assertEqual(plan.stage_count, 2)
        self.assertEqual(plan.stages[0].request_indexes, (0,))
        self.assertEqual(plan.stages[1].request_indexes, (1,))


if __name__ == "__main__":
    unittest.main()
