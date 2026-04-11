__ContractDeployedEvent = LogEvent(
    "ContractDeployed",
    {
        "name": {"type": str, "idx": True},
        "owner": {"type": str},
        "developer": {"type": str, "idx": True},
    },
    contract="submission",
    name="ContractDeployedEvent",
)

__ContractOwnerChangedEvent = LogEvent(
    "ContractOwnerChanged",
    {
        "contract": {"type": str, "idx": True},
        "previous_owner": {"type": str},
        "new_owner": {"type": str, "idx": True},
    },
    contract="submission",
    name="ContractOwnerChangedEvent",
)


@__export("submission")
def submit_contract(
    name: str, code: str, owner: Any = None, constructor_args: dict = {}
):
    assert isinstance(name, str) and name != "", (
        "Contract name must be a non-empty string!"
    )
    if ctx.caller != "sys":
        assert name.startswith("con_"), "Contract must start with con_!"

    assert len(name) <= 64, "Contract name length exceeds 64 characters!"
    assert name[0].isascii() and name[0].isalpha() and name[0].islower(), (
        "Contract name must start with a lowercase ASCII letter!"
    )
    assert all(
        c.isascii() and (c.islower() or c.isdigit() or c == "_")
        for c in name
    ), (
        "Contract name must contain only lowercase ASCII letters, digits, "
        "and underscores!"
    )
    assert owner is None or (
        isinstance(owner, str) and owner != ""
    ), "Owner must be None or a non-empty string!"

    __Contract().submit(
        name=name,
        code=code,
        owner=owner,
        constructor_args=constructor_args,
        developer=ctx.caller,
        deployer=ctx.caller,
        initiator=ctx.signer,
    )
    __ContractDeployedEvent(
        {
            "name": name,
            "owner": owner or "",
            "developer": ctx.caller,
        }
    )


@__export("submission")
def change_developer(contract: str, new_developer: str):
    assert isinstance(contract, str) and contract != "", (
        "Contract must be a non-empty string!"
    )
    assert isinstance(new_developer, str) and new_developer != "", (
        "New developer must be a non-empty string!"
    )
    d = __Contract()._driver.get_var(
        contract=contract, variable="__developer__"
    )
    assert ctx.caller == d, "Sender is not current developer!"

    __Contract()._driver.set_var(
        contract=contract, variable="__developer__", value=new_developer
    )


@__export("submission")
def change_owner(contract: str, new_owner: str):
    assert isinstance(contract, str) and contract != "", (
        "Contract must be a non-empty string!"
    )
    current_owner = __Contract()._driver.get_var(
        contract=contract, variable="__owner__"
    )
    assert current_owner not in (None, ""), "Contract has no runtime owner!"
    assert ctx.caller == current_owner, "Sender is not current owner!"
    assert isinstance(new_owner, str) and new_owner != "", (
        "New owner must be a non-empty string!"
    )

    __Contract()._driver.set_var(
        contract=contract, variable="__owner__", value=new_owner
    )
    __ContractOwnerChangedEvent(
        {
            "contract": contract,
            "previous_owner": current_owner,
            "new_owner": new_owner,
        }
    )
