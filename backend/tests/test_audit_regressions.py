"""
Regression tests for the FileSanitizer security audit (2026-10-17).

Each test encodes the SECURE behaviour expected after remediation of a
confirmed audit finding. A test that FAILS means the corresponding
vulnerability is present (regression); a test that PASSES means the fix
is in place.

Finding IDs correspond to SECURITY_AUDIT_REPORT.md / security_audit_backlog.json.

NOTE ON DEPLOYMENT DRIFT (verified 2026-10-17): at audit time the remediations
existed only in the working tree -- they were neither committed (git HEAD
74f4171 still contained the vulnerable code) nor deployed (the running
filesanitizer-api container image, built 2026-10-16, still ran the vulnerable
code). These tests therefore PASS against the fixed source on disk but FAIL
against the then-deployed container. Re-run inside the actually deployed
image to prove the running service is fixed, not just the source tree.
"""

import ipaddress
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# FS-SEC-001 -- Unauthenticated command injection -> container root
# ---------------------------------------------------------------------------

class TestFsSec001CommandInjection:
    """The domain/IP forensic CLI runner must never pass attacker-controlled
    indicators to a shell, and must reject shell metacharacters outright."""

    INJECTION_TARGETS = [
        "example.com; id",
        "example.com && id",
        "example.com | id",
        "example.com`id`",
        "example.com$(id)",
        "example.com\nid",
        "$(touch /tmp/pwned)",
        "a.com; sudo nmap --script=/tmp/x.nse localhost",
        "a.com > /tmp/x",
        "a.com'||id||'",
    ]

    def test_is_safe_indicator_rejects_shell_metacharacters(self):
        from app.analyzers.ip_domain_forensics import _is_safe_indicator
        for payload in self.INJECTION_TARGETS:
            assert _is_safe_indicator(payload) is False, (
                f"_is_safe_indicator accepted injection payload: {payload!r}"
            )

    def test_is_safe_indicator_accepts_legitimate_indicators(self):
        from app.analyzers.ip_domain_forensics import _is_safe_indicator
        for good in ["example.com", "sub.example.co.uk", "8.8.8.8", "1.1.1.1",
                     "xn--80ak6aa92e.com", "a-b-c.example.org"]:
            assert _is_safe_indicator(good) is True, (
                f"_is_safe_indicator rejected legitimate indicator: {good!r}"
            )

    def test_execute_cli_tool_rejects_injection_without_executing(self):
        from app.analyzers.ip_domain_forensics import _execute_cli_tool
        tool = {"name": "dig", "command": "dig {target}"}
        res = _execute_cli_tool(tool, "example.com; touch /tmp/fsaudit_regress", is_ip=False, primary_ip=None)
        assert res.get("executed") is False
        assert res.get("status") == "rejected"

    def test_no_shell_true_in_forensics_module(self):
        """shell=True anywhere in the forensic runner is a hard fail."""
        src = Path(__file__).resolve().parents[1] / "app" / "analyzers" / "ip_domain_forensics.py"
        text = src.read_text()
        # Allow the string to appear only inside comments/docstrings, never as an argument.
        offending = [
            ln for ln in text.splitlines()
            if "shell=True" in ln and not ln.lstrip().startswith("#")
            and "NO shell=True" not in ln and "without shell=True" not in ln
        ]
        assert offending == [], f"shell=True used as argument:\n" + "\n".join(offending)


# ---------------------------------------------------------------------------
# FS-SEC-001 (privesc leg) -- passwordless sudo nmap in the image
# ---------------------------------------------------------------------------

def test_fs_sec_001_dockerfile_has_no_passwordless_sudo():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    text = dockerfile.read_text()
    assert "NOPASSWD" not in text, "Dockerfile grants passwordless sudo (privilege escalation)"
    assert "/etc/sudoers.d/appuser" not in text, "Dockerfile writes a sudoers rule for appuser"


# ---------------------------------------------------------------------------
# FS-SEC-002 -- Forgeable admin JWT (default secret) + default credentials
# ---------------------------------------------------------------------------

def test_fs_sec_002_secret_key_not_shipped_placeholder_in_prod(monkeypatch):
    """In production the signing key must not remain the shipped placeholder."""
    import importlib
    import app.config as config_mod

    placeholder = "filesanitizer-jwt-secret-key-32byte-minimum-secure-2026"
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("ADMIN_SECRET_KEY", placeholder)
    # Re-instantiate Settings so the field validator runs against the env above.
    fresh = importlib.reload(config_mod)
    try:
        assert fresh.settings.ADMIN_SECRET_KEY != placeholder, (
            "ADMIN_SECRET_KEY is still the shipped placeholder in production -- tokens are forgeable offline"
        )
        assert len(fresh.settings.ADMIN_SECRET_KEY) >= 32
    finally:
        # Restore the module to a clean default-env state for other tests.
        monkeypatch.undo()
        importlib.reload(config_mod)


def test_fs_sec_002_login_uses_constant_time_comparison():
    import inspect
    from app.core import settings_store
    src = inspect.getsource(settings_store.verify_admin_login)
    assert "compare_digest" in src, "verify_admin_login must use secrets.compare_digest (timing-safe)"


# ---------------------------------------------------------------------------
# FS-SEC-003 -- Broken access control on the job/file API
# ---------------------------------------------------------------------------

def test_fs_sec_003_list_all_jobs_requires_auth():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    res = client.get("/api/files")
    assert res.status_code in (401, 403), (
        f"GET /api/files returned {res.status_code} unauthenticated -- "
        "job enumeration is not access-controlled"
    )


# ---------------------------------------------------------------------------
# FS-SEC-004 -- Reflective wildcard CORS with credentials
# ---------------------------------------------------------------------------

def test_fs_sec_004_cors_not_wildcard_with_credentials():
    from app.main import app
    from starlette.middleware.cors import CORSMiddleware
    cors = next((m for m in app.user_middleware if m.cls is CORSMiddleware), None)
    assert cors is not None, "CORS middleware missing"
    origins = cors.kwargs.get("allow_origins", [])
    allow_credentials = cors.kwargs.get("allow_credentials", False)
    if allow_credentials:
        assert "*" not in origins, (
            "allow_origins='*' combined with allow_credentials=True reflects any origin"
        )


# ---------------------------------------------------------------------------
# FS-DET-001 -- Identification precedence: email misclassified as html/svg
# ---------------------------------------------------------------------------

class TestFsDet001Identification:
    def _write(self, tmp_path, name, data: bytes) -> Path:
        p = tmp_path / name
        p.write_bytes(data)
        return p

    def test_eml_with_leading_html_detected_as_email(self, tmp_path):
        from app.analyzers.identification import detect_file_type
        # An RFC822 message whose body begins with markup must still be email.
        raw = (
            b"From: attacker@evil.test\r\n"
            b"To: victim@corp.test\r\n"
            b"Subject: <html> invoice\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body><svg onload=alert(1)></svg></body></html>\r\n"
        )
        p = self._write(tmp_path, "payload.eml", raw)
        mime, category, _ = detect_file_type(p, "payload.eml")
        assert category == "email", f"email misclassified as {category!r} ({mime}) -- forensics skipped"

    def test_rfc822_headers_without_extension_detected_as_email(self, tmp_path):
        from app.analyzers.identification import detect_file_type
        raw = (
            b"Received: from mail.evil.test\r\n"
            b"From: a@evil.test\r\n"
            b"Subject: hi\r\n\r\n"
            b"<html>body</html>"
        )
        p = self._write(tmp_path, "nodotext", raw)
        _, category, _ = detect_file_type(p, "nodotext")
        assert category == "email"

    def test_genuine_html_still_detected_as_html(self, tmp_path):
        from app.analyzers.identification import detect_file_type
        p = self._write(tmp_path, "page.html", b"<!doctype html><html><body>hi</body></html>")
        _, category, _ = detect_file_type(p, "page.html")
        assert category == "html"

    def test_genuine_svg_still_detected_as_svg(self, tmp_path):
        from app.analyzers.identification import detect_file_type
        p = self._write(tmp_path, "img.svg", b'<svg xmlns="http://www.w3.org/2000/svg"></svg>')
        _, category, _ = detect_file_type(p, "img.svg")
        assert category == "svg"


# ---------------------------------------------------------------------------
# FS-DET-002 -- Hybrid Analysis tags mislabelled as MITRE ATT&CK IDs
# ---------------------------------------------------------------------------

def test_fs_det_002_only_real_attck_ids_reported():
    import inspect
    from app.analyzers import reputation_client
    src = inspect.getsource(reputation_client.HybridAnalysisClient)
    # The fix validates each id against a Txxxx[.yyy] pattern before labelling it ATT&CK.
    assert "mitre_attcks" in src
    assert ("T\\d{4}" in src or "T\\\\d{4}" in src), (
        "HybridAnalysisClient no longer validates ATT&CK IDs with a Txxxx regex"
    )


# ---------------------------------------------------------------------------
# FS-INFO-002 -- Verbose internal errors leaked to clients
# ---------------------------------------------------------------------------

def test_fs_info_002_fetch_errors_are_generic():
    import inspect
    from app.api import files
    src = inspect.getsource(files)
    assert 'detail=f"Failed to fetch remote file: {e}"' not in src
    assert 'detail=f"Failed to investigate asset: {e}"' not in src
