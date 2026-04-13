import ast
import builtins


def _existing_ast_types(*names):
    return {
        node for name in names if (node := ast.__dict__.get(name)) is not None
    }


ALLOWED_BUILTINS = {
    "Exception",
    "False",
    "None",
    "True",
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "chr",
    "dict",
    "divmod",
    "filter",
    "float",
    "format",
    "hex",
    "int",
    "isinstance",
    "issubclass",
    "import",
    "len",
    "list",
    "map",
    "max",
    "min",
    "oct",
    "ord",
    "pow",
    "range",
    "reversed",
    "round",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
}

ILLEGAL_BUILTINS = set(dir(builtins)) - ALLOWED_BUILTINS

ILLEGAL_AST_TYPES = {
    ast.AsyncFor,
    ast.AsyncFunctionDef,
    ast.AsyncWith,
    ast.Await,
    ast.ClassDef,
    ast.GeneratorExp,
    ast.ImportFrom,
    ast.Interactive,
    ast.Lambda,
    ast.MatMult,
    ast.Nonlocal,
    ast.Set,
    ast.SetComp,
    ast.Try,
    ast.With,
    ast.Yield,
    ast.YieldFrom,
} | _existing_ast_types("Ellipsis", "Suite")

ALLOWED_ANNOTATION_TYPES = {
    "Any",
    "bool",
    "datetime.datetime",
    "datetime.timedelta",
    "dict",
    "float",
    "int",
    "list",
    "str",
}
