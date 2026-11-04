"""Default EVTX severity rules: Sysmon event IDs that signal tampering or injection are critical."""

from app.core.settings_store import DEFAULT_SETTINGS


def test_sysmon_injection_and_tampering_events_are_critical():
    rules = DEFAULT_SETTINGS["evtx_severity_rules"]
    # 8 CreateRemoteThread, 10 ProcessAccess, 25 ProcessTampering (hollowing/herpaderping)
    for event_id in ("8", "10", "25"):
        assert rules[event_id] == "critical", event_id
