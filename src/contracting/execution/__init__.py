from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = [
    "ExecutionAccess",
    "ExecutionRequest",
    "ParallelBatchExecutor",
    "ParallelExecutionPlanner",
    "ParallelExecutionStats",
    "ParallelPlan",
    "ParallelStage",
    "SpeculativeExecutionController",
]


if TYPE_CHECKING:
    from contracting.execution.parallel import (
        ExecutionAccess,
        ExecutionRequest,
        ParallelBatchExecutor,
        ParallelExecutionPlanner,
        ParallelExecutionStats,
        ParallelPlan,
        ParallelStage,
        SpeculativeExecutionController,
    )


def __getattr__(name: str):
    if name in __all__:
        from contracting.execution.parallel import (
            ExecutionAccess,
            ExecutionRequest,
            ParallelBatchExecutor,
            ParallelExecutionPlanner,
            ParallelExecutionStats,
            ParallelPlan,
            ParallelStage,
            SpeculativeExecutionController,
        )

        exports = {
            "ExecutionAccess": ExecutionAccess,
            "ExecutionRequest": ExecutionRequest,
            "ParallelBatchExecutor": ParallelBatchExecutor,
            "ParallelExecutionPlanner": ParallelExecutionPlanner,
            "ParallelExecutionStats": ParallelExecutionStats,
            "ParallelPlan": ParallelPlan,
            "ParallelStage": ParallelStage,
            "SpeculativeExecutionController": (SpeculativeExecutionController),
        }
        return exports[name]
    raise AttributeError(name)
