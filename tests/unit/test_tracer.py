from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from contracting.execution.tracer import MAX_STAMPS, Tracer


def sample_contract():
    __contract__ = True
    return 1


class TestTracer(TestCase):
    def make_frame(
        self, globals_dict=None, lasti=0, code=sample_contract.__code__
    ):
        return SimpleNamespace(
            f_code=code,
            f_globals=globals_dict or {},
            f_lasti=lasti,
        )

    @patch("contracting.execution.tracer.sys.settrace")
    def test_start_stop_and_reset_manage_state(self, settrace):
        tracer = Tracer()
        tracer.cost = 99
        tracer.call_count = 8
        tracer.stamp_supplied = 123
        tracer.last_frame_mem_usage = 11
        tracer.total_mem_usage = 22

        tracer.start()

        self.assertTrue(tracer.is_started())
        self.assertEqual(settrace.call_args_list[0].args, (tracer.trace_func,))
        self.assertEqual(tracer.get_stamp_used(), 0)
        self.assertEqual(tracer.call_count, 0)

        tracer.stop()

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args_list[-1].args, (None,))

        tracer.cost = 7
        tracer.stamp_supplied = 9
        tracer.last_frame_mem_usage = 10
        tracer.total_mem_usage = 11
        tracer.call_count = 12

        tracer.reset()

        self.assertEqual(tracer.get_stamp_used(), 0)
        self.assertEqual(tracer.stamp_supplied, 0)
        self.assertEqual(tracer.get_last_frame_mem_usage(), 0)
        self.assertEqual(tracer.get_total_mem_usage(), 0)
        self.assertEqual(tracer.call_count, 0)

    @patch("contracting.execution.tracer.sys.settrace")
    def test_add_cost_stops_when_stamp_limit_is_exceeded(self, settrace):
        tracer = Tracer()
        tracer.started = True
        tracer.set_stamp(3)

        with self.assertRaises(AssertionError):
            tracer.add_cost(4)

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args.args, (None,))

    @patch("contracting.execution.tracer.sys.settrace")
    def test_add_cost_stops_when_max_stamp_limit_is_exceeded(self, settrace):
        tracer = Tracer()
        tracer.started = True
        tracer.set_stamp(MAX_STAMPS)

        with self.assertRaises(AssertionError):
            tracer.add_cost(MAX_STAMPS + 1)

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args.args, (None,))

    def test_trace_func_ignores_non_contract_frames(self):
        tracer = Tracer()
        frame = self.make_frame()

        result = tracer.trace_func(frame, "line", None)

        self.assertIsNone(result)
        self.assertEqual(tracer.call_count, 1)
        self.assertEqual(tracer.get_stamp_used(), 0)
        self.assertEqual(tracer.get_total_mem_usage(), 0)

    @patch("contracting.execution.tracer.sys.settrace")
    def test_trace_func_stops_when_call_count_limit_is_exceeded(self, settrace):
        tracer = Tracer()
        tracer.started = True
        tracer.max_call_count = 0

        with self.assertRaises(AssertionError):
            tracer.trace_func(self.make_frame(), "line", None)

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args.args, (None,))

    def test_trace_func_tracks_contract_cost_and_memory(self):
        tracer = Tracer()
        tracer.set_stamp(MAX_STAMPS)
        frame = self.make_frame(globals_dict={"__contract__": True})

        with (
            patch.object(tracer, "get_memory_usage", side_effect=[128, 256]),
            patch.object(tracer, "get_opcode", return_value=0),
        ):
            result = tracer.trace_func(frame, "line", None)

        self.assertIs(result.__self__, tracer)
        self.assertEqual(result.__func__, tracer.trace_func.__func__)
        self.assertEqual(tracer.get_stamp_used(), 2)
        self.assertEqual(tracer.get_last_frame_mem_usage(), 256)
        self.assertEqual(tracer.get_total_mem_usage(), 128)

    @patch("contracting.execution.tracer.sys.settrace")
    def test_trace_func_stops_when_memory_limit_is_exceeded(self, settrace):
        tracer = Tracer()
        tracer.started = True
        tracer.set_stamp(MAX_STAMPS)
        tracer.last_frame_mem_usage = 1
        frame = self.make_frame(globals_dict={"__contract__": True})

        with (
            patch.object(
                tracer, "get_memory_usage", return_value=600 * 1024 * 1024
            ),
            patch.object(tracer, "get_opcode", return_value=0),
            self.assertRaises(AssertionError),
        ):
            tracer.trace_func(frame, "line", None)

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args.args, (None,))

    @patch("contracting.execution.tracer.sys.settrace")
    def test_trace_func_stops_when_cost_limit_is_exceeded(self, settrace):
        tracer = Tracer()
        tracer.started = True
        tracer.set_stamp(1)
        tracer.last_frame_mem_usage = 1
        frame = self.make_frame(globals_dict={"__contract__": True})

        with (
            patch.object(tracer, "get_memory_usage", return_value=1),
            patch.object(tracer, "get_opcode", return_value=85),
            self.assertRaises(AssertionError),
        ):
            tracer.trace_func(frame, "line", None)

        self.assertFalse(tracer.is_started())
        self.assertEqual(settrace.call_args.args, (None,))

    @patch("contracting.execution.tracer.dis.get_instructions")
    def test_get_opcode_caches_instructions_and_defaults_to_zero(
        self, get_instructions
    ):
        tracer = Tracer()
        code = sample_contract.__code__
        get_instructions.return_value = [SimpleNamespace(offset=8, opcode=12)]

        self.assertEqual(tracer.get_opcode(code, 8), 12)
        self.assertEqual(tracer.get_opcode(code, 99), 0)
        self.assertEqual(get_instructions.call_count, 1)

    @patch("contracting.execution.tracer.psutil.Process")
    def test_get_memory_usage_returns_process_rss(self, process_cls):
        process_cls.return_value.memory_info.return_value.rss = 321

        tracer = Tracer()

        self.assertEqual(tracer.get_memory_usage(), 321)
