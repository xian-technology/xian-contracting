from types import ModuleType

import nacl

from contracting.stdlib.bridge.crypto_resources import TEXT_LIMIT, utf8_size


def verify(vk: str, msg: str, signature: str):
    utf8_size(vk, 64, "verify key")
    utf8_size(msg, TEXT_LIMIT, "verify message")
    utf8_size(signature, 128, "verify signature")
    vk = bytes.fromhex(vk)
    msg = msg.encode()
    signature = bytes.fromhex(signature)

    vk = nacl.signing.VerifyKey(vk)
    try:
        vk.verify(msg, signature)
    except Exception:
        return False
    return True


def key_is_valid(key: str):
    """Check the 64-character ASCII hexadecimal shape of a public or private key."""
    if not isinstance(key, str):
        raise TypeError("key must be a string")
    return len(key) == 64 and all(char in "0123456789abcdefABCDEF" for char in key)


crypto_module = ModuleType("crypto")
crypto_module.verify = verify
crypto_module.key_is_valid = key_is_valid

exports = {"crypto": crypto_module}
