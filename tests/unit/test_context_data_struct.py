"""Shared host context exposes explicit metadata."""

from unittest import TestCase

from contracting.execution.runtime import Context


class TestContext(TestCase):
    def setUp(self):
        self.base = {
            "caller": "caller",
            "signer": "signer",
            "this": "con_host",
            "owner": "owner",
            "entry": ("con_entry", "run"),
            "submission_name": "con_child",
        }
        self.context = Context(self.base)

    def test_get_state_returns_the_explicit_host_metadata(self):
        self.assertEqual(self.context._get_state(), self.base)

    def test_properties_read_all_host_metadata_fields(self):
        for name, value in self.base.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(self.context, name), value)

    def test_context_properties_are_read_only(self):
        for name in self.base:
            with self.subTest(name=name):
                with self.assertRaises(AttributeError):
                    setattr(self.context, name, "replacement")
