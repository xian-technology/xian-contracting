from unittest import TestCase

from contracting.execution.runtime import rt
from contracting.storage.contract import Contract, XIAN_EXECUTION_MODE_ENV_KEY
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

    def test_deploy_requires_artifacts_under_xian_vm_execution_mode(self):
        driver = Driver()
        previous_mode = rt.env.get(XIAN_EXECUTION_MODE_ENV_KEY)
        rt.env[XIAN_EXECUTION_MODE_ENV_KEY] = "xian_vm_v1"
        try:
            with self.assertRaisesRegex(
                TypeError,
                "requires deployment_artifacts",
            ):
                Contract.deploy(
                    name="con_vm_probe",
                    code="@export\ndef ping():\n    return 'pong'\n",
                    driver=driver,
                )
        finally:
            if previous_mode is None:
                rt.env.pop(XIAN_EXECUTION_MODE_ENV_KEY, None)
            else:
                rt.env[XIAN_EXECUTION_MODE_ENV_KEY] = previous_mode
            driver.flush_full()
