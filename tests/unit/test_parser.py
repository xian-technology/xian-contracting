from unittest import TestCase

from contracting.compilation import parser


class TestParser(TestCase):
    def test_methods_for_contract_annotation_matrix(self):
        annotations = [
            "bool",
            "int",
            "float",
            "str",
            "list[int]",
            "list[float]",
            "dict[str, int]",
            "dict[str, list[int]]",
            "set[int]",
            "frozenset[str]",
            "datetime.datetime",
            "datetime.timedelta",
        ]
        args = ", ".join(
            f"arg_{index}: {annotation}" for index, annotation in enumerate(annotations)
        )
        code = f"""
@export
def typed({args}):
    return None
"""

        got = parser.methods_for_contract(code)

        self.assertEqual(
            [
                {
                    "name": "typed",
                    "arguments": [
                        {"name": f"arg_{index}", "type": annotation}
                        for index, annotation in enumerate(annotations)
                    ],
                }
            ],
            got,
        )

    def test_methods_for_contract_single_function(self):
        code = """
@export
def test_func(arg: str, arg2: int):
    return arg, arg2
        """

        compiled = code

        expected = [
            {
                "name": "test_func",
                "arguments": [{"name": "arg", "type": "str"}, {"name": "arg2", "type": "int"}],
            }
        ]

        got = parser.methods_for_contract(compiled)

        self.assertListEqual(expected, got)

    def test_methods_for_contract_datetime(self):
        code = """
@export
def thing(arg: datetime.datetime, arg2: datetime.timedelta):
    return 123        
"""
        compiled = code
        got = parser.methods_for_contract(compiled)

        expected = [
            {
                "name": "thing",
                "arguments": [
                    {"name": "arg", "type": "datetime.datetime"},
                    {"name": "arg2", "type": "datetime.timedelta"},
                ],
            }
        ]

        self.assertEqual(expected, got)

    def test_methods_for_contract_subscript_annotations(self):
        code = """
@export
def route(amounts: list[float], path: list[int]):
    return amounts, path
"""
        got = parser.methods_for_contract(code)

        expected = [
            {
                "name": "route",
                "arguments": [
                    {"name": "amounts", "type": "list[float]"},
                    {"name": "path", "type": "list[int]"},
                ],
            }
        ]

        self.assertEqual(expected, got)

    def test_methods_for_contract_nested_subscript_annotations(self):
        code = """
@export
def route(routes: dict[str, list[int]], range_: tuple[int, ...]):
    return routes, range_
"""
        got = parser.methods_for_contract(code)

        expected = [
            {
                "name": "route",
                "arguments": [
                    {"name": "routes", "type": "dict[str, list[int]]"},
                    {"name": "range_", "type": "tuple[int, ...]"},
                ],
            }
        ]

        self.assertEqual(expected, got)

    def test_methods_for_contract_ignores_complex_annotation_expressions(self):
        code = """
@export
def route(value: __import__('os').system('true')):
    return value
"""
        got = parser.methods_for_contract(code)

        expected = [{"name": "route", "arguments": [{"name": "value"}]}]

        self.assertEqual(expected, got)

    def test_methods_for_contract_ignores_excessive_annotation_depth(self):
        annotation = "list[" * 20 + "int" + "]" * 20
        code = f"""
@export
def route(value: {annotation}):
    return value
"""
        got = parser.methods_for_contract(code)

        expected = [{"name": "route", "arguments": [{"name": "value"}]}]

        self.assertEqual(expected, got)

    def test_methods_for_historical_source_omit_private_prefixes(self):
        code = """
@export
def test_func(arg: str, arg2: int):
    return arg, arg2
    
@export
def another_one(something: Any, something_else: dict):
    a = 123
    b = 456
    return __add(a, b)
    
def __add(a, b):
    return a + b
"""
        compiled = code

        expected = [
            {
                "name": "test_func",
                "arguments": [{"name": "arg", "type": "str"}, {"name": "arg2", "type": "int"}],
            },
            {
                "name": "another_one",
                "arguments": [
                    {"name": "something", "type": "Any"},
                    {"name": "something_else", "type": "dict"},
                ],
            },
        ]

        got = parser.methods_for_contract(compiled)

        self.assertListEqual(expected, got)

    def test_variables_for_contract_passes_election_house(self):
        code = """
# Convenience
I = importlib

#Policies
policies = Hash()

# Policy interface
policy_interface = [
    I.Func('vote', args=('vk', 'obj')),
    I.Func('current_value')
]

@export
def register_policy(contract: str):
    if policies[contract] is None:
        # Attempt to import the contract to make sure it is already submitted
        p = I.import_module(contract)

        # Assert ownership is election_house and interface is correct
        assert I.owner_of(p) == ctx.this, \
            'Election house must control the policy contract!'

        assert I.enforce_interface(p, policy_interface), \
            'Policy contract does not follow the correct interface'

        policies[contract] = True
    else:
        raise Exception('Policy already registered')

@export
def current_value_for_policy(policy: str):
    assert policies.get(policy) is not None, 'Invalid policy.'
    p = I.import_module(policy)

    return p.current_value()

@export
def vote(policy: str, value: Any):
    # Verify policy has been registered
    assert policies.get(policy) is not None, 'Invalid policy.'
    p = I.import_module(policy)

    p.vote(vk=ctx.caller, obj=value)
    """

        compiled = code

        got = parser.variables_for_contract(compiled)

        expected = {"variables": [], "hashes": ["policies"]}

        self.assertDictEqual(got, expected)

    def test_variables_for_contract_multiple_variables(self):
        code = """
v1 = Variable()
v2 = Variable()
v3 = Variable()

@export
def something():
   return 1
        """

        compiled = code

        got = parser.variables_for_contract(compiled)

        expected = {"variables": ["v1", "v2", "v3"], "hashes": []}

        self.assertDictEqual(got, expected)

    def test_variables_for_contract_multiple_hashes(self):
        code = """
h1 = Hash()
h2 = Hash()
h3 = Hash()

@export
def something():
   return 1
        """

        compiled = code

        got = parser.variables_for_contract(compiled)

        expected = {"variables": [], "hashes": ["h1", "h2", "h3"]}

        self.assertDictEqual(got, expected)

    def test_variables_mix(self):
        code = """
v1 = Variable()
v2 = Variable()
v3 = Variable()
h1 = Hash()
h2 = Hash()
h3 = Hash()

@export
def something():
   return 1
        """

        compiled = code

        got = parser.variables_for_contract(compiled)

        expected = {"variables": ["v1", "v2", "v3"], "hashes": ["h1", "h2", "h3"]}

        self.assertDictEqual(got, expected)

    def test_variables_for_contract_ignores_non_storage_calls(self):
        code = """
metadata = I.Func('vote')
settings['owner'] = Hash()
storage = Hash()

@export
def something():
   return 1
        """

        got = parser.variables_for_contract(code)

        expected = {"variables": [], "hashes": ["storage"]}

        self.assertDictEqual(got, expected)

    def test_variables_remove_only_private_prefix(self):
        code = """
__private = Variable()
_public = Variable()
__private_hash = Hash()
_public_hash = Hash()

@export
def something():
   return 1
        """

        got = parser.variables_for_contract(code)

        expected = {"variables": ["private", "_public"], "hashes": ["private_hash", "_public_hash"]}

        self.assertDictEqual(got, expected)
