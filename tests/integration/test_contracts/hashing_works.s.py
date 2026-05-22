@export
def t_sha3_text(s: str):
    return hashlib.sha3_text(s)

@export
def t_sha3_hex(s: str):
    return hashlib.sha3_hex(s)

@export
def t_sha256_text(s: str):
    return hashlib.sha256_text(s)

@export
def t_sha256_hex(s: str):
    return hashlib.sha256_hex(s)
