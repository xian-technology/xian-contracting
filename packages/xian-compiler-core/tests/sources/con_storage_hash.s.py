balances = Hash(default_value=0)


@export
def bump(key: str, amount: int):
    balances[key] += amount
    return balances[key]
