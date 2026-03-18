from unittest import TestCase

from contracting import constants
from contracting.execution import runtime
from contracting.execution.tracer import StampExceededError


class TestRuntimeLifecycle(TestCase):
    def tearDown(self):
        runtime.rt.tracer.stop()
        runtime.rt.clean_up()

    def test_set_up_starts_tracer_when_metering(self):
        runtime.rt.set_up(stmps=1000, meter=True)
        self.assertTrue(runtime.rt.tracer.is_started())

    def test_set_up_does_not_start_tracer_without_metering(self):
        runtime.rt.set_up(stmps=1000, meter=False)
        self.assertFalse(runtime.rt.tracer.is_started())

    def test_clean_up_stops_tracer(self):
        runtime.rt.set_up(stmps=1000, meter=True)
        runtime.rt.clean_up()
        self.assertFalse(runtime.rt.tracer.is_started())


class TestTracerMetering(TestCase):
    def tearDown(self):
        runtime.rt.tracer.stop()
        runtime.rt.clean_up()

    def test_tracer_works_with_registered_code(self):
        runtime.rt.set_up(stmps=1_000_000, meter=True)
        code = compile("x = max([i for i in range(2)])", "<test>", "exec")
        runtime.rt.tracer.register_code(code)
        exec(code)
        runtime.rt.tracer.stop()
        self.assertGreater(runtime.rt.tracer.get_stamp_used(), 0)

    def test_more_work_costs_more(self):
        runtime.rt.set_up(stmps=1_000_000, meter=True)
        code_big = compile("x = max([i for i in range(100)])", "<test>", "exec")
        runtime.rt.tracer.register_code(code_big)
        exec(code_big)
        runtime.rt.tracer.stop()
        used_big = runtime.rt.tracer.get_stamp_used()
        runtime.rt.clean_up()

        runtime.rt.set_up(stmps=10_000_000, meter=True)
        code_small = compile("x = 1", "<test>", "exec")
        runtime.rt.tracer.register_code(code_small)
        exec(code_small)
        runtime.rt.tracer.stop()
        used_small = runtime.rt.tracer.get_stamp_used()

        self.assertGreater(used_big, used_small)

    def test_add_cost_directly(self):
        runtime.rt.set_up(stmps=1000, meter=True)
        runtime.rt.tracer.add_cost(900)
        runtime.rt.tracer.stop()
        self.assertEqual(runtime.rt.tracer.get_stamp_used(), 900)


class TestWriteDeduction(TestCase):
    def tearDown(self):
        runtime.rt.tracer.stop()
        runtime.rt.clean_up()

    def test_deduct_write_adjusts_total_writes(self):
        runtime.rt.set_up(stmps=100_000, meter=True)
        runtime.rt.deduct_write("a", "bad")
        self.assertEqual(runtime.rt.writes, 4)

    def test_deduct_write_adds_stamp_cost(self):
        runtime.rt.set_up(stmps=100_000, meter=True)
        cost_before = runtime.rt.tracer.get_stamp_used()
        runtime.rt.deduct_write("key", "val")
        self.assertGreater(runtime.rt.tracer.get_stamp_used(), cost_before)

    def test_deduct_write_fails_if_too_many_writes(self):
        runtime.rt.set_up(stmps=100_000_000, meter=True)
        runtime.rt.deduct_write("a", "bad")
        with self.assertRaises((AssertionError, StampExceededError)):
            runtime.rt.deduct_write("a", "b" * 128 * 1024)


class TestReadDeduction(TestCase):
    def tearDown(self):
        runtime.rt.tracer.stop()
        runtime.rt.clean_up()

    def test_deduct_read_adds_cost(self):
        runtime.rt.set_up(stmps=100_000, meter=True)
        cost_before = runtime.rt.tracer.get_stamp_used()
        runtime.rt.deduct_read("mykey", "myvalue")
        self.assertGreater(runtime.rt.tracer.get_stamp_used(), cost_before)


class TestReturnValueDeduction(TestCase):
    def tearDown(self):
        runtime.rt.tracer.stop()
        runtime.rt.clean_up()

    def test_deduct_return_value_adds_cost(self):
        runtime.rt.set_up(stmps=100_000, meter=True)
        cost_before = runtime.rt.tracer.get_stamp_used()
        runtime.rt.deduct_return_value({"value": "ok"})
        self.assertGreater(runtime.rt.tracer.get_stamp_used(), cost_before)

    def test_deduct_return_value_fails_if_too_large(self):
        runtime.rt.set_up(stmps=10_000_000, meter=True)
        with self.assertRaises(AssertionError):
            runtime.rt.deduct_return_value(
                "a" * (constants.MAX_RETURN_VALUE_SIZE + 1)
            )
