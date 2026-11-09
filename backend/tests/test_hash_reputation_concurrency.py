"""
PERF-3: the independent external hash-reputation lookups must run concurrently.

They are all keyed on the same sha256 and the clients are internally defensive
(return a dict, never raise), so overlapping the network I/O must not change which
results come back -- only the total latency, from the sum of the lookups to ~max.
"""

import time

from app.core.job_manager import job_manager
from app.core.settings_store import settings_store
from app.analyzers import virustotal_client as vt_mod
from app.analyzers import reputation_client as rc


DELAY = 0.3


def _slow(tag):
    def _f(*args, **kwargs):
        time.sleep(DELAY)
        return {"tag": tag}
    return _f


def _enable_all(monkeypatch):
    monkeypatch.setattr(settings_store, "is_global_enabled", lambda k: True)
    monkeypatch.setattr(settings_store, "is_external_allowed", lambda k: True)
    monkeypatch.setattr(settings_store, "is_check_enabled", lambda f, c: True)
    monkeypatch.setattr(settings_store, "get_api_key", lambda k: "key")
    monkeypatch.setattr(vt_mod.VirusTotalClient, "lookup_file_hash", staticmethod(_slow("vt")))
    monkeypatch.setattr(rc.CirclHashlookupClient, "check_hash", staticmethod(_slow("circl")))
    monkeypatch.setattr(rc.ThreatFoxClient, "check_hash", staticmethod(_slow("threatfox")))
    monkeypatch.setattr(rc.MalwareBazaarClient, "check_hash", staticmethod(_slow("malwarebazaar")))
    monkeypatch.setattr(rc.HybridAnalysisClient, "check_hash", staticmethod(_slow("hybrid_analysis")))
    monkeypatch.setattr(rc.AlienVaultOTXClient, "check_indicator", staticmethod(_slow("alienvault_otx")))


def test_all_reputations_fetched_and_concurrent(monkeypatch):
    _enable_all(monkeypatch)
    t0 = time.time()
    rep = job_manager._fetch_hash_reputations("a" * 64, "pdf")
    elapsed = time.time() - t0

    # Every enabled lookup returned, routed to the right key
    assert rep == {
        "vt": {"tag": "vt"},
        "circl": {"tag": "circl"},
        "threatfox": {"tag": "threatfox"},
        "malwarebazaar": {"tag": "malwarebazaar"},
        "hybrid_analysis": {"tag": "hybrid_analysis"},
        "alienvault_otx": {"tag": "alienvault_otx"},
    }
    # Concurrent: six 0.3s calls finish well under the 1.8s they would take serially.
    assert elapsed < DELAY * 3, f"lookups did not run concurrently (took {elapsed:.2f}s)"


def test_empty_hash_short_circuits(monkeypatch):
    _enable_all(monkeypatch)
    assert job_manager._fetch_hash_reputations("", "pdf") == {}


def test_disabled_intel_dispatches_nothing(monkeypatch):
    # Nothing enabled -> no lookups dispatched, empty result (no network, instant).
    monkeypatch.setattr(settings_store, "is_global_enabled", lambda k: False)
    monkeypatch.setattr(settings_store, "is_external_allowed", lambda k: False)
    monkeypatch.setattr(settings_store, "is_check_enabled", lambda f, c: False)
    monkeypatch.setattr(settings_store, "get_api_key", lambda k: "")
    assert job_manager._fetch_hash_reputations("b" * 64, "pdf") == {}
