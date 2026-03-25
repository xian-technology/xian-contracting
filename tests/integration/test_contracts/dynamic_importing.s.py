@export
def balance_for_token(tok: str, account: str):
    t = importlib.import_module(tok)
    return t.balance_of(account=account)


@export
def dynamic_balance_for_token(tok: str, function_name: str, account: str):
    return importlib.call(
        tok,
        function_name,
        {"account": account},
    )


@export
def dynamic_balance_for_token_module(
    tok: str, function_name: str, account: str
):
    t = importlib.import_module(tok)
    return importlib.call(
        t,
        function_name,
        {"account": account},
    )


@export
def dynamic_call_with_bad_kwargs(tok: str, function_name: str):
    return importlib.call(
        tok,
        function_name,
        {"wrong": "value"},
    )


@export
def dynamic_private_call(tok: str, function_name: str):
    return importlib.call(tok, function_name)


@export
def dynamic_non_export_call(tok: str, function_name: str):
    return importlib.call(tok, function_name)


@export
def dynamic_owner_call(tok: str):
    return importlib.call(tok, "owner_of_this")


@export
def dynamic_ctx_call(tok: str, account: str):
    return importlib.call(
        tok,
        "describe",
        {"account": account},
    )


@export
def only_erc20(tok: str, account: str):
    t = importlib.import_module(tok)
    assert enforce_erc20(t), "You cannot use a non-ERC20 standard token!!"

    return t.balance_of(account=account)


@export
def is_erc20_compatible(tok: str):
    interface = [
        importlib.Func("transfer", args=("amount", "to")),
        importlib.Func("balance_of", args=("account",)),
        importlib.Func("total_supply"),
        importlib.Func("allowance", args=("owner", "spender")),
        importlib.Func("approve", args=("amount", "to")),
        importlib.Func("transfer_from", args=("amount", "to", "main_account")),
        importlib.Var("supply", Variable),
        importlib.Var("balances", Hash),
    ]

    t = importlib.import_module(tok)

    return importlib.enforce_interface(t, interface)


def enforce_erc20(m):
    interface = [
        importlib.Func("transfer", args=("amount", "to")),
        importlib.Func("balance_of", args=("account",)),
        importlib.Func("total_supply"),
        importlib.Func("allowance", args=("owner", "spender")),
        importlib.Func("approve", args=("amount", "to")),
        importlib.Func("transfer_from", args=("amount", "to", "main_account")),
        importlib.Var("supply", Variable),
        importlib.Var("balances", Hash),
    ]

    return importlib.enforce_interface(m, interface)
