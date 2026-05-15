import unittest
from dataclasses import replace

from contracting.execution.parallel import (
    ExecutionAccess,
    SpeculativeExecutionController,
)


def access(index, sender, reads=(), writes=()):
    return ExecutionAccess(
        index=index,
        sender=sender,
        nonce=0,
        reads=frozenset(reads),
        prefix_reads=frozenset(),
        writes=frozenset(writes),
        additive_writes=frozenset(),
        status=0,
    )


class EstimatingController(SpeculativeExecutionController):
    def __init__(self, estimates):
        self.estimates = estimates
        self.speculated_batches = []
        super().__init__(
            enabled=True,
            workers=1,
            min_batch_size=1,
            use_access_estimates=True,
        )

    def _estimate_access(self, *, index, request):
        estimate = self.estimates.get(index)
        if estimate is None:
            return None
        return replace(estimate, index=index)

    def _execute_serial_request(self, request):
        return {
            "id": request["id"],
            "access": self.estimates.get(request["id"]),
        }

    def _speculate_many(self, *, requests, base_pending_writes):
        self.speculated_batches.append([request["id"] for request in requests])
        return [self._execute_serial_request(request) for request in requests]

    def _normalize_access(self, *, index, request, output):
        estimate = output.get("access")
        if estimate is None:
            return None
        return replace(estimate, index=index)

    def _apply_speculative_output(self, output):
        return None


class SpeculativeControllerEstimateTests(unittest.TestCase):
    def test_access_estimates_skip_unknown_requests(self):
        controller = EstimatingController(
            {
                1: access(1, "bob", writes={"state:bob"}),
                2: access(2, "carol", writes={"state:carol"}),
            }
        )

        outputs, stats = controller.execute(
            requests=[{"id": 0}, {"id": 1}, {"id": 2}]
        )

        self.assertEqual([output["id"] for output in outputs], [0, 1, 2])
        self.assertEqual(controller.speculated_batches, [[1, 2]])
        self.assertEqual(stats.estimated_known_requests, 2)
        self.assertEqual(stats.estimated_unknown_requests, 1)
        self.assertEqual(stats.speculative_wave_count, 1)
        self.assertEqual(stats.speculative_accepted, 2)
        self.assertEqual(stats.serial_prefiltered, 1)

    def test_access_estimates_stop_wave_before_declared_conflict(self):
        controller = EstimatingController(
            {
                0: access(0, "alice", writes={"state:shared"}),
                1: access(1, "bob", writes={"state:shared"}),
                2: access(2, "carol", writes={"state:carol"}),
            }
        )

        outputs, stats = controller.execute(
            requests=[{"id": 0}, {"id": 1}, {"id": 2}]
        )

        self.assertEqual([output["id"] for output in outputs], [0, 1, 2])
        self.assertEqual(controller.speculated_batches, [[1, 2]])
        self.assertEqual(stats.estimated_stage_count, 2)
        self.assertEqual(stats.estimated_parallelizable_requests, 1)
        self.assertEqual(stats.speculative_wave_count, 1)
        self.assertEqual(stats.speculative_accepted, 2)
        self.assertEqual(stats.serial_prefiltered, 1)


if __name__ == "__main__":
    unittest.main()
