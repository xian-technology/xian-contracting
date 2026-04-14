ContractDeployedEvent = LogEvent(
    "ContractDeployed",
    {
        "name": {"type": str, "idx": True},
        "owner": {"type": str},
        "developer": {"type": str, "idx": True},
    },
)

ContractOwnerChangedEvent = LogEvent(
    "ContractOwnerChanged",
    {
        "contract": {"type": str, "idx": True},
        "previous_owner": {"type": str},
        "new_owner": {"type": str, "idx": True},
    },
)


def assert_safe_contract_name(name: str):
    assert isinstance(name, str) and name != "", (
        "Contract name must be a non-empty string!"
    )
    if ctx.caller != "sys":
        assert name.startswith("con_"), "Contract must start with con_!"

    assert len(name) <= 64, "Contract name length exceeds 64 characters!"
    assert name[0].isascii() and name[0].isalpha() and name[0].islower(), (
        "Contract name must start with a lowercase ASCII letter!"
    )

    for char in name:
        assert char.isascii() and (
            char.islower() or char.isdigit() or char == "_"
        ), (
            "Contract name must contain only lowercase ASCII letters, digits, "
            "and underscores!"
        )


@export
def submit_contract(
    name: str,
    code: str = None,
    owner: str = None,
    constructor_args: dict = None,
    deployment_artifacts: dict = None,
):
    assert_safe_contract_name(name)
    assert code is None or (
        isinstance(code, str) and code != ""
    ), "code must be None or a non-empty string!"
    assert owner is None or (
        isinstance(owner, str) and owner != ""
    ), "Owner must be None or a non-empty string!"
    if constructor_args is None:
        constructor_args = {}
    assert deployment_artifacts is None or isinstance(
        deployment_artifacts, dict
    ), "deployment_artifacts must be None or a dict!"
    assert (
        code is not None or deployment_artifacts is not None
    ), "submit_contract requires code or deployment_artifacts!"

    Contract.deploy(
        name=name,
        code=code,
        deployment_artifacts=deployment_artifacts,
        owner=owner,
        constructor_args=constructor_args,
        developer=ctx.caller,
        deployer=ctx.caller,
        initiator=ctx.signer,
    )
    ContractDeployedEvent(
        {
            "name": name,
            "owner": owner or "",
            "developer": ctx.caller,
        }
    )


@export
def change_developer(contract: str, new_developer: str):
    assert isinstance(contract, str) and contract != "", (
        "Contract must be a non-empty string!"
    )
    assert isinstance(new_developer, str) and new_developer != "", (
        "New developer must be a non-empty string!"
    )

    current_developer = Contract.get_info(contract)["developer"]
    assert ctx.caller == current_developer, "Sender is not current developer!"

    Contract.set_developer(contract, new_developer)


@export
def change_owner(contract: str, new_owner: str):
    assert isinstance(contract, str) and contract != "", (
        "Contract must be a non-empty string!"
    )
    assert isinstance(new_owner, str) and new_owner != "", (
        "New owner must be a non-empty string!"
    )

    current_owner = Contract.get_info(contract)["owner"]
    assert current_owner not in (None, ""), "Contract has no runtime owner!"
    assert ctx.caller == current_owner, "Sender is not current owner!"

    Contract.set_owner(contract, new_owner)
    ContractOwnerChangedEvent(
        {
            "contract": contract,
            "previous_owner": current_owner,
            "new_owner": new_owner,
        }
    )
