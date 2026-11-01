import ast

MAX_ANNOTATION_TYPE_LENGTH = 128
MAX_ANNOTATION_DEPTH = 16


def _annotation_type(annotation):
    rendered = _format_annotation(annotation)
    if rendered is None:
        return None
    if len(rendered) > MAX_ANNOTATION_TYPE_LENGTH:
        return None
    return rendered


def _format_annotation(annotation, depth=0):
    if annotation is None or depth > MAX_ANNOTATION_DEPTH:
        return None

    if isinstance(annotation, ast.Name):
        return annotation.id

    if isinstance(annotation, ast.Attribute):
        value = _format_annotation(annotation.value, depth + 1)
        if value is None:
            return None
        return f"{value}.{annotation.attr}"

    if isinstance(annotation, ast.Subscript):
        value = _format_annotation(annotation.value, depth + 1)
        slice_value = _format_annotation(annotation.slice, depth + 1)
        if value is None or slice_value is None:
            return None
        return f"{value}[{slice_value}]"

    if isinstance(annotation, ast.Tuple):
        elements = [_format_annotation(element, depth + 1) for element in annotation.elts]
        if any(element is None for element in elements):
            return None
        return ", ".join(elements)

    if isinstance(annotation, ast.Constant):
        if annotation.value is Ellipsis:
            return "..."
        if annotation.value is None:
            return "None"
        if isinstance(annotation.value, str):
            return repr(annotation.value)

    return None


def methods_for_contract(contract_source: str):
    tree = ast.parse(contract_source)

    function_defs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]

    funcs = []
    for definition in function_defs:
        func_name = definition.name

        if func_name.startswith("__"):
            continue

        kwargs = []

        for arg in definition.args.args:
            a = _annotation_type(arg.annotation)

            argument = {"name": arg.arg}
            if a is not None:
                argument["type"] = a
            kwargs.append(argument)

        funcs.append({"name": func_name, "arguments": kwargs})

    return funcs


def _storage_constructor(value):
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Name):
        return None
    if value.func.id != "__xian_orm_declaration__":
        return value.func.id
    if len(value.args) < 3 or not isinstance(value.args[0], ast.Name):
        return None
    return value.args[0].id


def variables_for_contract(contract_source: str):
    tree = ast.parse(contract_source)

    assigns = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            assigns.append(node)

        if isinstance(node, ast.FunctionDef):
            break

    variables = []
    hashes = []
    destinations = {"Variable": variables, "Hash": hashes}

    for assign in assigns:
        if not isinstance(assign.targets[0], ast.Name):
            continue
        destination = destinations.get(_storage_constructor(assign.value))
        if destination is not None:
            destination.append(assign.targets[0].id.removeprefix("__"))

    return {"variables": variables, "hashes": hashes}
