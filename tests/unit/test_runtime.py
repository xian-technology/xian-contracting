"""The shared native host owns context and environment, never a Python evaluator."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from contracting.execution.runtime import Context, Runtime


def state(contract, caller):
    return {
        "this": contract,
        "caller": caller,
        "signer": "alice",
        "owner": None,
        "entry": ("con_entry", "run"),
        "submission_name": None,
    }


def test_runtime_state_is_isolated_per_thread():
    runtime = Runtime()
    barrier = Barrier(2)

    def worker(tag):
        runtime.env = {"tag": tag}
        runtime.context = Context(state(f"con_{tag}", tag))
        barrier.wait()
        return dict(runtime.env), runtime.context.caller

    with ThreadPoolExecutor(max_workers=2) as executor:
        alpha = executor.submit(worker, "alpha")
        beta = executor.submit(worker, "beta")

    assert alpha.result() == ({"tag": "alpha"}, "alpha")
    assert beta.result() == ({"tag": "beta"}, "beta")
    assert dict(runtime.env) == {}
    assert runtime.context.this is None


def test_runtime_instances_do_not_share_environment_or_context():
    alpha, beta = Runtime(), Runtime()
    alpha.env["tag"] = "alpha"
    alpha.context._base_state["this"] = "con_alpha"
    assert dict(beta.env) == {}
    assert beta.context.this is None


def test_assigning_host_environment_copies_the_input_mapping():
    runtime = Runtime()
    original = {"chain_id": "local"}
    runtime.env = original
    original["chain_id"] = "changed"
    assert runtime.env["chain_id"] == "local"
    runtime.env["input_hash"] = "abc"
    assert len(runtime.env) == 2
    del runtime.env["input_hash"]
    assert len(runtime.env) == 1
    assert dict(runtime.env) == {"chain_id": "local"}
