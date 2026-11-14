"""Formatting a referenced (heap) value: f-string conversions and format().

Revision 14 dropped a charge for a copy of the referenced object that no
longer happens (it fed a removed binary-float check); these scenarios pin
the element work of formatting a referenced list, dict and nested list.
"""

VALUES = {
    "list": "list(range(40))",
    "dict": "{str(n): n for n in range(30)}",
    "nested": "[[n, str(n)] for n in range(20)]",
}
EXPRESSIONS = {
    "fstring": "f'{value}'",
    "fstring_repr": "f'{value!r}'",
    "fstring_ascii": "f'{value!a}'",
    "format": "format(value)",
}


def formatting_cases():
    return [
        {
            "id": f"formatting_reference_{kind}_{name}",
            "vm_profile": "xian_vm_v2",
            "source": (
                f"@export\ndef probe():\n    value = {value}\n    return len({expression})\n"
            ),
        }
        for kind, value in VALUES.items()
        for name, expression in EXPRESSIONS.items()
    ]
