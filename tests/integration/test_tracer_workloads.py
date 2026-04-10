import sys
import textwrap
from unittest import TestCase

from contracting.execution.tracer import MAX_CHI, create_tracer


def _meter(mode: str, source: str) -> int:
    tracer = create_tracer(mode)
    code = compile(textwrap.dedent(source), "<workload>", "exec")
    tracer.set_chi(MAX_CHI)
    tracer.start()
    tracer.register_code(code)
    exec(code, {})
    tracer.stop()
    used = tracer.get_chi_used()
    tracer.reset()
    return used


class TestTracerWorkloads(TestCase):
    def setUp(self):
        if sys.version_info < (3, 12):
            self.skipTest("tracer workloads require sys.monitoring support")
        try:
            create_tracer("native_instruction_v1").reset()
        except ImportError as exc:
            self.skipTest(str(exc))

    def test_branch_heavy_workloads_charge_less_under_native_tracer(self):
        cases = {
            "short_circuit": """
                def f(a, b, c):
                    return a and b and c

                for _ in range(50):
                    f(False, True, True)
            """,
            "ternary": """
                def f(x):
                    return 1 if x else 2

                for _ in range(50):
                    f(True)
            """,
            "multi_statement_line": """
                def f(x):
                    if x: y = 1; z = 2
                    return 1

                for _ in range(50):
                    f(False)
            """,
            "loop_branch_mix": """
                def f(n):
                    total = 0
                    for i in range(n):
                        if i % 3 == 0:
                            total += i
                    return total

                for _ in range(5):
                    f(20)
            """,
        }

        for source in cases.values():
            with self.subTest(source=source):
                python_cost = _meter("python_line_v1", source)
                native_cost = _meter("native_instruction_v1", source)
                self.assertGreater(python_cost, native_cost)

    def test_backend_costs_are_deterministic_per_run(self):
        source = """
            def f(n):
                total = 0
                for i in range(n):
                    if i % 2 == 0:
                        total += i
                return total

            for _ in range(10):
                f(15)
        """

        for mode in ("python_line_v1", "native_instruction_v1"):
            with self.subTest(mode=mode):
                first = _meter(mode, source)
                second = _meter(mode, source)
                self.assertEqual(first, second)
