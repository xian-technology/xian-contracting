import currency

TransferEvent = LogEvent(
    "Transfer",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)


@export
def transfer(amount: int, to: str):
    sender = ctx.caller
    currency.transfer(amount=amount, to=to)
    TransferEvent({"from": sender, "to": to, "amount": amount})
