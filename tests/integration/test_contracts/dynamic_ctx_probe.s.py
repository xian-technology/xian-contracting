@export
def describe(account: str):
    return {
        "caller": ctx.caller,
        "signer": ctx.signer,
        "this": ctx.this,
        "entry": f"{ctx.entry[0]}.{ctx.entry[1]}",
        "account": account,
    }
