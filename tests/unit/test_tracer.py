import opcode
import types
from unittest import TestCase
from unittest.mock import patch

from contracting.execution.tracer import (
    DEFAULT_COST,
    CU_COSTS,
    DEFAULT_TRACER_MODE,
    MAX_CALL_COUNT,
    MAX_STAMPS,
    SUPPORTED_TRACER_MODES,
    CallLimitExceededError,
    StampExceededError,
    Tracer,
    create_tracer,
    get_default_cost_opcodes,
    get_tracer_policy,
    get_uncategorized_default_cost_opcodes,
    resolve_tracer_mode,
)


def make_code(source="x = 1\ny = 2\n"):
    return compile(source, "<test>", "exec")


class TestTracerLifecycle(TestCase):
    def setUp(self):
        self.tracer = Tracer()

    def tearDown(self):
        self.tracer.reset()

    def test_start_resets_counters(self):
        self.tracer.cost = 99
        self.tracer.call_count = 8
        self.tracer.stamp_supplied = 123

        self.tracer.start()

        self.assertTrue(self.tracer.is_started())
        self.assertEqual(self.tracer.get_stamp_used(), 0)
        self.assertEqual(self.tracer.call_count, 0)

    def test_stop_idempotent(self):
        self.tracer.start()
        self.tracer.stop()
        self.tracer.stop()
        self.assertFalse(self.tracer.is_started())

    def test_reset_clears_all_state(self):
        self.tracer.start()
        self.tracer.cost = 7
        self.tracer.stamp_supplied = 9
        self.tracer.call_count = 12

        self.tracer.reset()

        self.assertEqual(self.tracer.get_stamp_used(), 0)
        self.assertEqual(self.tracer.stamp_supplied, 0)
        self.assertEqual(self.tracer.call_count, 0)
        self.assertFalse(self.tracer.is_started())


class TestOpcodeCosts(TestCase):
    def test_call_opcode_cost_is_named_not_legacy_indexed(self):
        call_opcode = opcode.opmap.get("CALL")
        if call_opcode is not None:
            self.assertEqual(CU_COSTS[call_opcode], 1610)

    def test_instrumented_opcode_cost_tracks_base_opcode(self):
        inst_call = opcode.opmap.get("INSTRUMENTED_CALL")
        call = opcode.opmap.get("CALL")
        if inst_call is not None and call is not None and inst_call < 256:
            self.assertEqual(CU_COSTS[inst_call], CU_COSTS[call])


class TestTracerSelection(TestCase):
    def test_default_mode_is_supported(self):
        self.assertIn(DEFAULT_TRACER_MODE, SUPPORTED_TRACER_MODES)
        self.assertEqual(resolve_tracer_mode(None), DEFAULT_TRACER_MODE)

    def test_backend_policies_use_backend_specific_event_limits(self):
        python_policy = get_tracer_policy("python_line_v1")
        native_policy = get_tracer_policy("native_instruction_v1")

        self.assertEqual(python_policy.max_events, MAX_CALL_COUNT)
        self.assertGreater(native_policy.max_events, python_policy.max_events)
        self.assertEqual(native_policy.max_stamps, MAX_STAMPS)
        self.assertGreater(native_policy.max_stamps, 6_500_000)

    def test_factory_returns_python_tracer_by_default(self):
        tracer = create_tracer()
        self.assertIsInstance(tracer, Tracer)
        tracer.reset()


class TestAddCost(TestCase):
    def setUp(self):
        self.tracer = Tracer()

    def tearDown(self):
        self.tracer.reset()

    def test_add_cost_accumulates(self):
        self.tracer.start()
        self.tracer.set_stamp(1000)
        self.tracer.add_cost(100)
        self.tracer.add_cost(200)
        self.assertEqual(self.tracer.get_stamp_used(), 300)

    def test_add_cost_raises_on_stamp_exceeded(self):
        self.tracer.start()
        self.tracer.set_stamp(3)

        with self.assertRaises(StampExceededError):
            self.tracer.add_cost(4)

    def test_add_cost_raises_on_max_stamps_exceeded(self):
        self.tracer.start()
        self.tracer.set_stamp(MAX_STAMPS + 100)

        with self.assertRaises(StampExceededError):
            self.tracer.add_cost(MAX_STAMPS + 1)


class TestLineCallback(TestCase):
    def setUp(self):
        self.tracer = Tracer()

    def tearDown(self):
        self.tracer.reset()

    def test_callback_charges_line_cost(self):
        self.tracer.set_stamp(MAX_STAMPS)
        self.tracer.start()
        code = make_code()
        line_number = code.co_firstlineno

        self.tracer._line_callback(code, line_number)

        self.assertEqual(
            self.tracer.get_stamp_used(),
            self.tracer._line_cost(code, line_number),
        )
        self.assertEqual(self.tracer.call_count, 1)

    def test_callback_raises_on_call_limit(self):
        self.tracer.start()
        self.tracer.set_stamp(MAX_STAMPS)
        self.tracer.call_count = MAX_CALL_COUNT

        with self.assertRaises(CallLimitExceededError):
            self.tracer._line_callback(make_code(), 1)

    def test_callback_raises_on_stamp_exceeded(self):
        self.tracer.start()
        self.tracer.set_stamp(1)
        self.tracer.cost = 1

        with self.assertRaises(StampExceededError):
            self.tracer._line_callback(make_code(), 1)

    def test_callback_has_no_process_side_effects(self):
        self.tracer.start()
        self.tracer.set_stamp(MAX_STAMPS)
        code = make_code()

        with patch(
            "contracting.execution.python_tracer.sys.monitoring.set_local_events"
        ) as set_local_events:
            self.tracer.register_code(code)
            for _ in range(10):
                self.tracer._line_callback(code, code.co_firstlineno)

        self.assertGreaterEqual(set_local_events.call_count, 1)

    def test_line_cost_uses_real_line_numbers(self):
        code = compile(
            "def f(a, b, c):\n    return a and b and c\n",
            "<test>",
            "exec",
        )

        self.tracer._line_cost(code, code.co_firstlineno)
        self.assertTrue(
            all(
                isinstance(key, int) and not isinstance(key, bool) and key > 0
                for key in self.tracer._line_costs[id(code)]
            )
        )


class TestCodeRegistration(TestCase):
    def setUp(self):
        self.tracer = Tracer()

    def tearDown(self):
        self.tracer.reset()

    def test_register_enables_events_recursively(self):
        code = compile("def foo():\n    return 1\n", "<test>", "exec")
        nested = [
            const
            for const in code.co_consts
            if isinstance(const, types.CodeType)
        ]
        self.tracer.start()

        with patch(
            "contracting.execution.python_tracer.sys.monitoring.set_local_events"
        ) as set_local_events:
            self.tracer.register_code(code)

        self.assertEqual(set_local_events.call_count, 1 + len(nested))

    def test_register_buffers_when_not_started(self):
        with patch(
            "contracting.execution.python_tracer.sys.monitoring.set_local_events"
        ) as set_local_events:
            self.tracer.register_code(make_code())

        set_local_events.assert_not_called()
        self.assertEqual(len(self.tracer._known_codes), 1)

    def test_reset_can_preserve_registered_metadata(self):
        code = make_code()
        self.tracer.register_code(code)
        self.tracer._line_cost(code, code.co_firstlineno)

        self.tracer.reset(clear_metadata=False)

        self.assertIn(id(code), self.tracer._known_codes)
        self.assertIn(id(code), self.tracer._line_costs)


class TestOpcodeSchedule(TestCase):
    def test_default_cost_opcodes_are_explicitly_approved(self):
        self.assertEqual(get_uncategorized_default_cost_opcodes(), [])

    def test_default_cost_opcode_list_is_not_empty(self):
        self.assertGreater(len(get_default_cost_opcodes()), 0)

    def test_default_cost_only_applies_to_explicit_opcode_set(self):
        for opname in get_default_cost_opcodes():
            code = opcode.opmap[opname]
            if code < len(CU_COSTS):
                self.assertEqual(CU_COSTS[code], DEFAULT_COST)
