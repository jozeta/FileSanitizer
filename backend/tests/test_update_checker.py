import pytest
from app.core.settings_store import settings_store
from app.api.settings import _parse_semver, check_for_updates

def test_parse_semver():
    assert _parse_semver("2.3.0") == (2, 3, 0)
    assert _parse_semver("v2.4.1") == (2, 4, 1)
    assert _parse_semver("3.0") == (3, 0, 0)
    assert _parse_semver("1") == (1, 0, 0)
    assert _parse_semver("2.4.0") > _parse_semver("2.3.0")
    assert _parse_semver("2.10.0") > _parse_semver("2.3.0")
    assert _parse_semver("2.3.0") == _parse_semver("v2.3.0")
    assert not (_parse_semver("2.2.9") > _parse_semver("2.3.0"))

def test_settings_store_ui_preferences_update_check():
    ui_prefs = settings_store.get_ui_preferences()
    assert "check_for_updates" in ui_prefs
    assert ui_prefs["check_for_updates"] is True

    # Test toggling
    settings_store.set_ui_preferences({"check_for_updates": False})
    assert settings_store.get_ui_preferences()["check_for_updates"] is False

    # Restore
    settings_store.set_ui_preferences({"check_for_updates": True})
    assert settings_store.get_ui_preferences()["check_for_updates"] is True

from app.config import settings as app_settings

def test_check_for_updates_endpoint_simulated():
    # Newer version
    res_newer = check_for_updates(force=True, simulate_version="3.0.0")
    assert res_newer["success"] is True
    assert res_newer["has_update"] is True
    assert res_newer["latest_version"] == "3.0.0"

    # Same version
    res_same = check_for_updates(force=True, simulate_version=app_settings.APP_VERSION)
    assert res_same["success"] is True
    assert res_same["has_update"] is False

    # Older version
    res_older = check_for_updates(force=True, simulate_version="2.0.0")
    assert res_older["success"] is True
    assert res_older["has_update"] is False
