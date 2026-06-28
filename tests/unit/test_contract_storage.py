from unittest import TestCase

from contracting.execution.runtime import rt
from contracting.storage.contract import XIAN_EXECUTION_MODE_ENV_KEY, Contract
from contracting.storage.driver import Driver


class TestContractStorage(TestCase):
    def test_driver_reads_pending_none_without_falling_back_to_disk(self):
        driver = Driver()
        try:
            key = driver.make_key("con_probe", "left_at", ["alice"])
            driver.set(key, "stale")
            driver.commit()

            driver.set(key, None)

            self.assertIsNone(driver.get(key))
            self.assertIsNone(driver.find(key))
        finally:
            driver.flush_full()

    def test_deploy_requires_source_code(self):
        driver = Driver()
        try:
            with self.assertRaisesRegex(
                TypeError,
                "requires non-empty source code",
            ):
                Contract.deploy(
                    name="con_vm_probe",
                    code=None,
                    driver=driver,
                )
        finally:
            driver.flush_full()
