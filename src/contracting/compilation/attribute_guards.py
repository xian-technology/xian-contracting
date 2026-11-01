"""Guard mutation targets without rewriting Python's assignment semantics."""

import ast

ATTRIBUTE_TARGET_HELPER = "__xian_attribute_target__"


class _GuardAttributeTargets(ast.NodeTransformer):
    def visit_Attribute(self, node):
        self.generic_visit(node)
        if not isinstance(node.ctx, (ast.Store, ast.Del)):
            return node
        receiver = node.value
        if (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id == ATTRIBUTE_TARGET_HELPER
        ):
            return node
        node.value = ast.copy_location(
            ast.Call(
                func=ast.Name(id=ATTRIBUTE_TARGET_HELPER, ctx=ast.Load()),
                args=[receiver, ast.Constant(node.attr)],
                keywords=[],
            ),
            receiver,
        )
        return node


def guard_attribute_targets(tree):
    return ast.fix_missing_locations(_GuardAttributeTargets().visit(tree))
