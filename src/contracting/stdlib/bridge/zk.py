"""The node's view of the zk verifier outside execution: the capability
probe and the proof caches it clears. Contract zk syscalls run in the VM
(vm-core ``block_host/zk.rs``) with the native library this module probes.
"""

from functools import lru_cache


@lru_cache(maxsize=1)
def _native_verifier_bindings():
    # The VM links the zk verifier and owns the node's proof caches.
    try:
        from xian_vm_core._native import (
            zk_clear_prepared_vk_cache,
            zk_clear_verified_proof_cache,
        )
    except ImportError:
        return None

    return {
        "clear_prepared_vk_cache": zk_clear_prepared_vk_cache,
        "clear_verified_proof_cache": zk_clear_verified_proof_cache,
    }


def is_available():
    return _native_verifier_bindings() is not None


def _clear_cache(name: str) -> None:
    bindings = _native_verifier_bindings()
    if bindings is not None:
        bindings[name]()


def clear_prepared_vk_cache():
    _clear_cache("clear_prepared_vk_cache")


def clear_verified_proof_cache():
    _clear_cache("clear_verified_proof_cache")
