I = importlib


def load_token(token: str):
    return I.import_module(token)


@export
def call_token(token: str, amount: int, to: str):
    module = load_token(token)
    module.transfer(amount=amount, to=to)
