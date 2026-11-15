balances = Hash(default_value=0)
metadata = Hash()
last_seen = Variable()

TransferEvent = LogEvent(
    "Transfer",
    {
        "sender": {"type": str, "idx": True},
        "to": {"type": str, "idx": True},
        "amount": {"type": (int, decimal)},
    },
)


@construct
def seed(supply: int = 1000, symbol: str = "TKN"):
    balances[ctx.caller] = supply
    metadata["symbol"] = symbol
    metadata["created"] = now


@export
def transfer(amount: decimal, to: str):
    """Move amount from the caller to `to`."""
    assert amount > 0, "Amount must be positive."
    assert balances[ctx.caller] >= amount, "Insufficient balance."
    balances[ctx.caller] -= amount
    balances[to] += amount
    last_seen.set(to)
    TransferEvent({"sender": ctx.caller, "to": to, "amount": amount})
    return balances[to]


@export
def add(a: decimal, b: decimal) -> decimal:
    return a + b


@export
def power(base: int, exponent: int) -> int:
    return base**exponent


@export
def describe(values: dict, when: datetime.datetime, span: datetime.timedelta):
    return {"values": values, "later": when + span, "keys": sorted(values.keys())}


@export
def remember(key: str, value: Any = None):
    metadata[key] = value
    return metadata[key]


@export
def spin(count: int):
    total = 0
    for i in range(count):
        total += i
    return total


@export
def balance_of(account: str):
    return balances[account]


@export
def distinct(items: list):
    metadata["distinct"] = set(items)
    return metadata["distinct"]
