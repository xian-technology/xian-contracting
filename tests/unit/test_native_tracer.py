from unittest import TestCase
from unittest.mock import ANY, patch

import pytest

from contracting.execution.native_tracer import TOOL_ID
from contracting.execution.tracer import ChiExceededError, create_tracer

pytestmark = pytest.mark.optional_native


class TestNativeTracer(TestCase):
    def setUp(self):
        self.tracer = create_tracer("native_instruction_v1")

    def tearDown(self):
        self.tracer.reset()

    def test_native_tracer_executes_registered_code(self):
        self.tracer.set_chi(1_000_000)
        self.tracer.start()
        code = compile("x = max([i for i in range(5)])", "<test>", "exec")
        self.tracer.register_code(code)
        exec(code)
        self.tracer.stop()
        self.assertGreater(self.tracer.get_chi_used(), 0)

    def test_native_tracer_registers_backend_callback_directly(self):
        with patch(
            "contracting.execution.native_tracer.sys.monitoring.register_callback"
        ) as register_callback:
            self.tracer.start()

        register_callback.assert_called_once_with(
            TOOL_ID,
            ANY,
            self.tracer._instruction_callback,
        )

    def test_native_tracer_raises_on_chi_exceeded(self):
        self.tracer.start()
        self.tracer.set_chi(1)
        with self.assertRaises(ChiExceededError):
            self.tracer.add_cost(2)

    def test_native_tracer_reset_can_preserve_registered_metadata(self):
        code = compile("x = max([i for i in range(5)])", "<test>", "exec")
        self.tracer.register_code(code)
        known_count = len(self.tracer._known_codes)

        with patch(
            "contracting.execution.native_tracer.sys.monitoring.set_local_events"
        ) as set_local_events:
            self.tracer.reset(clear_metadata=False)
            self.tracer.start()

        self.assertEqual(len(self.tracer._known_codes), known_count)
        self.assertEqual(set_local_events.call_count, known_count)
