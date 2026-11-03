"""Route Python harness formatting without rewriting persisted contract artifacts."""

import ast

FORMAT_ATTRIBUTE_HELPER = "__xian_format_attribute__"
FORMAT_FSTRING_HELPER = "__xian_format_fstring__"
_FORMAT_METHODS = frozenset({"format", "format_map"})


def _helper_call(name, args, location):
    return ast.copy_location(
        ast.Call(func=ast.Name(id=name, ctx=ast.Load()), args=args, keywords=[]), location
    )


def _is_guarded_formatted_value(node):
    return (
        node.conversion == -1
        and node.format_spec is None
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == FORMAT_FSTRING_HELPER
    )


class _GuardFormatting(ast.NodeTransformer):
    def visit_Attribute(self, node):
        self.generic_visit(node)
        if isinstance(node.ctx, ast.Load) and node.attr in _FORMAT_METHODS:
            return _helper_call(
                FORMAT_ATTRIBUTE_HELPER, [node.value, ast.Constant(node.attr)], node
            )
        return node

    def visit_FormattedValue(self, node):
        self.generic_visit(node)
        if _is_guarded_formatted_value(node):
            return node
        # Call arguments retain value -> nested specification -> conversion,
        # matching the VM even on Python versions that convert before the spec.
        formatted = _helper_call(
            FORMAT_FSTRING_HELPER,
            [
                node.value,
                node.format_spec if node.format_spec is not None else ast.Constant(""),
                ast.Constant(node.conversion),
            ],
            node,
        )
        # JoinedStr requires FormattedValue children. The helper already returns
        # the formatted string, so the outer interpolation has no conversion/spec.
        return ast.copy_location(
            ast.FormattedValue(value=formatted, conversion=-1, format_spec=None), node
        )


def guard_formatting(tree):
    return ast.fix_missing_locations(_GuardFormatting().visit(tree))
