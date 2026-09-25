import pytest
import ipaddress
from app.core.file_isolation import sanitize_filename, JobWorkspace
from app.network.ssrf import validate_url_for_ssrf, is_ip_blocked

def test_filename_sanitization_path_traversal():
    assert "passwd" in sanitize_filename("../../../../etc/passwd")
    assert "/" not in sanitize_filename("../../../../etc/passwd")
    assert "\\" not in sanitize_filename("..\\..\\Windows\\System32\\cmd.exe")
    assert "cmd.exe" in sanitize_filename("..\\..\\Windows\\System32\\cmd.exe")

def test_filename_sanitization_null_bytes():
    clean = sanitize_filename("malicious.pdf\x00.exe")
    assert "\x00" not in clean
    assert "malicious" in clean

def test_filename_length_limit():
    long_name = "a" * 300 + ".pdf"
    clean = sanitize_filename(long_name, max_length=50)
    assert len(clean) <= 60
    assert clean.endswith(".pdf")

def test_ssrf_blocked_ip_ranges():
    # Loopback
    assert is_ip_blocked(ipaddress.ip_address("127.0.0.1")) is True
    assert is_ip_blocked(ipaddress.ip_address("::1")) is True

    # Cloud metadata endpoint (169.254.169.254)
    assert is_ip_blocked(ipaddress.ip_address("169.254.169.254")) is True

    # Private RFC 1918 ranges
    assert is_ip_blocked(ipaddress.ip_address("10.0.0.1")) is True
    assert is_ip_blocked(ipaddress.ip_address("172.16.0.1")) is True
    assert is_ip_blocked(ipaddress.ip_address("192.168.1.100")) is True

    # Public IP should not be blocked
    assert is_ip_blocked(ipaddress.ip_address("8.8.8.8")) is False
    assert is_ip_blocked(ipaddress.ip_address("1.1.1.1")) is False

def test_ssrf_url_validation_localhost():
    is_safe, reason, _ = validate_url_for_ssrf("http://localhost:8080/admin")
    assert is_safe is False
    assert "Forbidden" in reason or "SSRF" in reason

def test_ssrf_url_validation_cloud_metadata():
    is_safe, reason, _ = validate_url_for_ssrf("http://169.254.169.254/latest/meta-data/")
    assert is_safe is False
    assert "SSRF" in reason or "private" in reason or "Forbidden" in reason
