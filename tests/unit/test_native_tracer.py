import sys
from unittest import TestCase

from contracting.execution.tracer import StampExceededError, create_tracer


class TestNativeTracer(TestCase):
    def setUp(self):
        if sys.version_info < (3, 12):
            self.skipTest("native tracer requires sys.monitoring support")
        try:
            self.tracer = create_tracer("native_instruction_v1")
        except ImportError as exc:
            self.skipTest(str(exc))

    def tearDown(self):
        self.tracer.reset()

    def test_native_tracer_executes_registered_code(self):
        self.tracer.set_stamp(1_000_000)
        self.tracer.start()
        code = compile("x = max([i for i in range(5)])", "<test>", "exec")
        self.tracer.register_code(code)
        exec(code)
        self.tracer.stop()
        self.assertGreater(self.tracer.get_stamp_used(), 0)

    def test_native_tracer_raises_on_stamp_exceeded(self):
        self.tracer.start()
        self.tracer.set_stamp(1)
        with self.assertRaises(StampExceededError):
            self.tracer.add_cost(2)
