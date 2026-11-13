"""A runtime feature's value with and without chain state."""

from types import SimpleNamespace

import pytest

from contracting.runtime_features import (
    RUNTIME_FEATURE_DRIVER_ATTR,
    runtime_feature_enabled,
    runtime_feature_without_state,
    set_driver_runtime_features,
)


def _driver(state=None):
    state = dict(state or {})
    return SimpleNamespace(get=state.get)


@pytest.mark.parametrize("installed", [None, {"zk": False}, {"zk": True}])
def test_without_state_the_installed_features_decide_else_the_default(installed):
    driver = _driver()
    if installed is not None:
        set_driver_runtime_features(driver, installed)
    expected = True if installed is None else installed["zk"]

    assert runtime_feature_without_state(driver, "zk") is expected
    assert runtime_feature_enabled(driver, "zk") is expected


def test_chain_state_is_not_what_the_fallback_reads():
    driver = _driver({"__runtime_features.zk": True})
    set_driver_runtime_features(driver, {"zk": False})

    assert runtime_feature_enabled(driver, "zk") is True
    assert runtime_feature_without_state(driver, "zk") is False
    assert getattr(driver, RUNTIME_FEATURE_DRIVER_ATTR) == {"zk": False}


def test_an_unsupported_feature_is_refused():
    with pytest.raises(ValueError, match="unsupported runtime feature"):
        runtime_feature_without_state(_driver(), "nope")
