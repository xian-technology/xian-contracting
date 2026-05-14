LedgerEvent = LogEvent(
    "LedgerTransfer",
    {
        "sender": indexed(str),
        "recipient": indexed(str),
        "amount": int,
    },
)

owner = Variable()
total_supply = Variable()
balances = Hash(default_value=0)
allowances = Hash(default_value=0)
audit_log = Hash()
audit_count = Variable()


def require_positive(amount: int):
    assert isinstance(amount, int), "amount must be an integer!"
    assert amount > 0, "amount must be positive!"


def record(action: str, account: str, amount: int):
    index = audit_count.get()
    audit_log[index, "action"] = action
    audit_log[index, "account"] = account
    audit_log[index, "amount"] = amount
    audit_count.set(index + 1)


@construct
def seed(initial_owner: str = None, supply: int = 0):
    if initial_owner is None or initial_owner == "":
        initial_owner = ctx.caller
    require_positive(supply)
    owner.set(initial_owner)
    total_supply.set(supply)
    balances[initial_owner] = supply
    audit_count.set(0)
    record("seed", initial_owner, supply)


@export
def transfer(amount: int, to: str):
    require_positive(amount)
    sender = ctx.caller
    assert isinstance(to, str) and to != "", "recipient required!"
    assert balances[sender] >= amount, "insufficient balance!"
    balances[sender] -= amount
    balances[to] += amount
    record("transfer", sender, amount)
    LedgerEvent({"sender": sender, "recipient": to, "amount": amount})
    return balances[sender]


@export
def approve(amount: int, spender: str):
    require_positive(amount)
    assert isinstance(spender, str) and spender != "", "spender required!"
    allowances[ctx.caller, spender] = amount
    record("approve", spender, amount)
    return allowances[ctx.caller, spender]


@export
def transfer_from(amount: int, owner_account: str, to: str):
    require_positive(amount)
    spender = ctx.caller
    assert allowances[owner_account, spender] >= amount, "allowance too low!"
    assert balances[owner_account] >= amount, "insufficient balance!"
    allowances[owner_account, spender] -= amount
    balances[owner_account] -= amount
    balances[to] += amount
    record("transfer_from", owner_account, amount)
    LedgerEvent({"sender": owner_account, "recipient": to, "amount": amount})
    return allowances[owner_account, spender]


@export
def batch_transfer(recipients: list[str], amounts: list[int]):
    assert len(recipients) == len(amounts), "batch length mismatch!"
    sent = 0
    i = 0
    while i < len(recipients):
        transfer(amounts[i], recipients[i])
        sent += amounts[i]
        i += 1
    return sent


@export
def snapshot(accounts: list[str]) -> dict:
    result = {}
    for account in accounts:
        result[account] = balances[account]
    return result
