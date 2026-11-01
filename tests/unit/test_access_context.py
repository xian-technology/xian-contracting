from unittest import TestCase

from contracting.execution.interface_subject import InterfaceSubject
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

    def test_subject_input_is_rejected_before_foreign_body(self):
        rt.env = {"__Driver": DummyDriver({})}
        calls = []

        @export_context("con_child")
        def consume(value):
            calls.append(value)
            return True

        subject = InterfaceSubject("function", "transfer", ("amount",))
        with self.assertRaisesRegex(TypeError, "interface subjects cannot cross"):
            consume({"nested": [subject]})
        self.assertEqual(calls, [])
        self.assertEqual(rt.context.this, "con_parent")

    def test_subject_return_is_rejected_after_foreign_context_exit(self):
        rt.env = {"__Driver": DummyDriver({})}
        subject = InterfaceSubject("storage", "__balance", storage_type="Variable")

        @export_context("con_child")
        def produce():
            return [subject]

        with self.assertRaisesRegex(TypeError, "interface subjects cannot cross"):
            produce()
        self.assertEqual(rt.context.this, "con_parent")
        self.assertEqual(rt.context._state, [])

    def test_subject_injection_into_mutable_argument_is_rejected(self):
        rt.env = {"__Driver": DummyDriver({})}
        subject = InterfaceSubject("function", "transfer", ())
        for raises in (False, True):
            with self.subTest(raises=raises):

                @export_context("con_child")
                def inject(value):
                    value.append(subject)
                    if raises:
                        raise ValueError("callee failed")
                    return True

                with self.assertRaisesRegex(TypeError, "interface subjects cannot cross"):
                    inject([])
                self.assertEqual(rt.context.this, "con_parent")
                self.assertEqual(rt.context._state, [])

    def test_local_export_can_use_subjects(self):
        rt.env = {"__Driver": DummyDriver({})}

        @export_context("con_parent")
        def local(value):
            return value

        subject = InterfaceSubject("function", "transfer", ())
        self.assertIs(local(subject), subject)

    def test_ordinary_shared_cycles_remain_supported(self):
        rt.env = {"__Driver": DummyDriver({})}

        @export_context("con_child")
        def identity(value):
            return value

        value = []
        value.append(value)
        self.assertIs(identity(value), value)
