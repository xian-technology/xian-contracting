"""Contract metadata helpers for explicit storage tooling."""

from contracting.names import assert_safe_contract_name
from contracting.storage.driver import (
    DEPLOYER_KEY,
    DEVELOPER_KEY,
    INITIATOR_KEY,
    OWNER_KEY,
    TIME_KEY,
    Driver,
)


class Contract:
    @staticmethod
    def _resolve_driver(driver: Driver | None = None) -> Driver:
        return driver or Driver()

    @classmethod
    def get_info(cls, name: str, *, driver: Driver | None = None) -> dict:
        assert_safe_contract_name(name)
        resolved_driver = cls._resolve_driver(driver)
        return {
            "name": name,
            "owner": resolved_driver.get_var(name, OWNER_KEY),
            "developer": resolved_driver.get_var(name, DEVELOPER_KEY),
            "deployer": resolved_driver.get_var(name, DEPLOYER_KEY),
            "initiator": resolved_driver.get_var(name, INITIATOR_KEY),
            "submitted": resolved_driver.get_var(name, TIME_KEY),
        }

    @classmethod
    def _set_metadata(cls, name, key, value, *, driver=None):
        assert_safe_contract_name(name)
        cls._resolve_driver(driver).set_var(name, key, value=value)

    @classmethod
    def set_owner(
        cls,
        name: str,
        new_owner: str,
        *,
        driver: Driver | None = None,
    ) -> None:
        cls._set_metadata(name, OWNER_KEY, new_owner, driver=driver)

    @classmethod
    def set_developer(
        cls,
        name: str,
        new_developer: str,
        *,
        driver: Driver | None = None,
    ) -> None:
        cls._set_metadata(name, DEVELOPER_KEY, new_developer, driver=driver)
