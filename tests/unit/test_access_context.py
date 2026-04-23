from unittest import TestCase

from contracting.execution.runtime import Context, rt
from contracting.stdlib.bridge.access import __export as export_context


class DummyDriver:
    def __init__(self, owners):
        self.owners = owners

    def get_owner(self, contract):
        return self.owners.get(contract)


class TestExportContext(TestCase):
    def setUp(self):
        self.original_env = dict(rt.env)
        self.original_base_state = dict(rt.context._base_state)
        rt.context = Context(
            base_state={
                "caller": "stu",
                "signer": "stu",
                "this": "con_parent",
                "owner": None,
                "entry": ("con_parent", "run"),
                "submission_name": None,
            }
        )

    def tearDown(self):
        rt.context = Context(base_state=self.original_base_state)
        rt.env = self.original_env

    def test_owner_mismatch_does_not_mutate_context_stack(self):
        rt.env = {"__Driver": DummyDriver({"con_child": "not_con_parent"})}

        cm = export_context("con_child")

        with self.assertRaisesRegex(Exception, "Caller is not the owner!"):
            cm.__enter__()

        self.assertEqual(rt.context.this, "con_parent")
        self.assertEqual(rt.context.caller, "stu")
        self.assertEqual(rt.context.signer, "stu")
        self.assertEqual(rt.context._state, [])
        self.assertEqual(rt.context._depth, [])

    def test_typecheck_rejects_argument_mismatch_before_context_entry(self):
        rt.env = {"__Driver": DummyDriver({"con_child": "con_parent"})}

        @export_context("con_child", typecheck=True)
        def typed(amount: int):
            return amount

        with self.assertRaisesRegex(
            TypeError,
            "Argument 'amount' must be <class 'int'>, got str!",
        ):
            typed("1")

        self.assertEqual(rt.context._state, [])
        self.assertEqual(rt.context._depth, [])

    def test_typecheck_rejects_return_mismatch_after_context_exit(self):
        rt.env = {"__Driver": DummyDriver({"con_child": "con_parent"})}

        @export_context("con_child", typecheck=True)
        def typed() -> bool:
            return 1

        with self.assertRaisesRegex(
            TypeError,
            "Return value must be <class 'bool'>, got int!",
        ):
            typed()

        self.assertEqual(rt.context._state, [])
        self.assertEqual(rt.context._depth, [])
