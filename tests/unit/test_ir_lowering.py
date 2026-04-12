import json
from unittest import TestCase

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.ir import (
    XIAN_IR_V1,
    XIAN_VM_HOST_CATALOG_V1,
)
from contracting.compilation.vm import XIAN_VM_V1_PROFILE, VmCompatibilityError


class TestCompilerIrLowering(TestCase):
    def test_lower_to_ir_emits_structural_module(self):
        source = """
import currency

balances = Hash(default_value=0)
metadata = Variable()
TransferEvent = LogEvent(
    "Transfer",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)

def load_token(token: str):
    return importlib.import_module(token)

@construct
def seed():
    metadata.set(now)

@export
def transfer(amount: int, to: str):
    sender = ctx.caller
    balances[sender] -= amount
    balances[to] += amount
    currency.transfer(amount=amount, to=to)
    token = load_token("currency")
    token.transfer(amount=amount, to=to)
    TransferEvent({"from": sender, "to": to, "amount": amount})
    return balances[to]
"""
        compiler = ContractingCompiler(module_name="sample_token")

        ir = compiler.lower_to_ir(source)
        functions_by_name = {function["name"]: function for function in ir["functions"]}
        seed = functions_by_name["seed"]
        transfer = functions_by_name["transfer"]

        self.assertEqual(ir["ir_version"], XIAN_IR_V1)
        self.assertEqual(ir["vm_profile"], XIAN_VM_V1_PROFILE)
        self.assertEqual(
            ir["host_catalog_version"], XIAN_VM_HOST_CATALOG_V1
        )
        self.assertEqual(ir["module_name"], "sample_token")
        self.assertEqual(len(ir["global_declarations"]), 3)
        self.assertEqual(len(ir["imports"]), 1)
        self.assertEqual(ir["global_declarations"][0]["node"], "storage_decl")
        self.assertEqual(ir["global_declarations"][1]["node"], "storage_decl")
        self.assertEqual(ir["global_declarations"][2]["node"], "event_decl")
        self.assertEqual(seed["visibility"], "construct")
        self.assertEqual(seed["body"][0]["value"]["syscall_id"], "storage.variable.set")
        self.assertEqual(transfer["visibility"], "export")
        self.assertEqual(transfer["body"][1]["node"], "storage_mutate")
        self.assertEqual(transfer["body"][1]["read_syscall_id"], "storage.hash.get")
        self.assertEqual(transfer["body"][1]["write_syscall_id"], "storage.hash.set")
        self.assertEqual(transfer["body"][3]["value"]["syscall_id"], "contract.export_call")
        self.assertEqual(transfer["body"][5]["value"]["syscall_id"], "contract.export_call")
        self.assertEqual(
            transfer["body"][6]["value"]["syscall_id"],
            "event.log.emit",
        )
        self.assertEqual(transfer["body"][7]["value"]["node"], "storage_get")
        dependency_ids = {item["id"] for item in ir["host_dependencies"]}
        self.assertIn("storage.hash.new", dependency_ids)
        self.assertIn("storage.variable.new", dependency_ids)
        self.assertIn("storage.variable.set", dependency_ids)
        self.assertIn("storage.hash.get", dependency_ids)
        self.assertIn("storage.hash.set", dependency_ids)
        self.assertIn("event.log.new", dependency_ids)
        self.assertIn("event.log.emit", dependency_ids)
        self.assertIn("contract.import", dependency_ids)
        self.assertIn("contract.export_call", dependency_ids)
        self.assertIn("event.indexed", dependency_ids)
        self.assertIn("context.caller", dependency_ids)
        self.assertIn("env.now", dependency_ids)

    def test_lower_to_ir_json_is_valid_json(self):
        source = """
@export
def render(values: list[int]) -> int:
    total = 0
    for value in values:
        total += value
    return total
"""
        compiler = ContractingCompiler(module_name="counter")

        payload = compiler.lower_to_ir_json(source)
        decoded = json.loads(payload)

        self.assertEqual(decoded["module_name"], "counter")
        self.assertEqual(decoded["functions"][0]["name"], "render")

    def test_lower_to_ir_raises_on_vm_profile_violation(self):
        source = """
@export
def countdown(value: int):
    while value > 0:
        value -= 1
    return value
"""
        compiler = ContractingCompiler(module_name="bad")

        with self.assertRaises(VmCompatibilityError):
            compiler.lower_to_ir(source)

    def test_lower_to_ir_records_decimal_runtime_usage(self):
        source = """
balances = Hash(default_value=decimal("0"))

@export
def quote():
    total = balances["alice"] + decimal("1.25")
    return isinstance(total, decimal)
"""
        compiler = ContractingCompiler(module_name="decimal_quote")

        ir = compiler.lower_to_ir(source)
        dependency_ids = {item["id"] for item in ir["host_dependencies"]}
        quote = next(function for function in ir["functions"] if function["name"] == "quote")

        self.assertIn("numeric.decimal.new", dependency_ids)
        self.assertEqual(quote["body"][0]["value"]["operator"], "add")

    def test_lower_to_ir_records_time_hash_and_crypto_runtime_usage(self):
        source = """
@export
def probe(vk: str, message: str, signature: str):
    start = datetime.datetime.strptime("2024-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
    end = now + datetime.timedelta(days=1, seconds=5)
    digest = hashlib.sha3(message)
    digest2 = hashlib.sha256(message)
    key_ok = crypto.key_is_valid(vk)
    sig_ok = crypto.verify(vk, message, signature)
    return end > start and key_ok and sig_ok and digest != digest2
"""
        compiler = ContractingCompiler(module_name="time_hash_crypto")

        ir = compiler.lower_to_ir(source)
        dependency_ids = {item["id"] for item in ir["host_dependencies"]}
        probe = next(function for function in ir["functions"] if function["name"] == "probe")

        self.assertIn("time.datetime.strptime", dependency_ids)
        self.assertIn("time.timedelta.new", dependency_ids)
        self.assertIn("hash.sha3_256", dependency_ids)
        self.assertIn("hash.sha256", dependency_ids)
        self.assertIn("crypto.key_is_valid", dependency_ids)
        self.assertIn("crypto.ed25519_verify", dependency_ids)
        self.assertIn("env.now", dependency_ids)

        self.assertEqual(probe["body"][0]["value"]["syscall_id"], "time.datetime.strptime")
        self.assertEqual(probe["body"][1]["value"]["operator"], "add")
        self.assertEqual(
            probe["body"][1]["value"]["right"]["syscall_id"],
            "time.timedelta.new",
        )
        self.assertEqual(probe["body"][2]["value"]["syscall_id"], "hash.sha3_256")
        self.assertEqual(probe["body"][3]["value"]["syscall_id"], "hash.sha256")
        self.assertEqual(probe["body"][4]["value"]["syscall_id"], "crypto.key_is_valid")
        self.assertEqual(probe["body"][5]["value"]["syscall_id"], "crypto.ed25519_verify")

    def test_lower_to_ir_serializes_large_int_constants_as_strings(self):
        source = """
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

@export
def probe():
    return FIELD_MODULUS
"""
        compiler = ContractingCompiler(module_name="bigint_constants")

        ir = compiler.lower_to_ir(source)

        self.assertEqual(
            ir["global_declarations"][0]["value"]["value"],
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        )
