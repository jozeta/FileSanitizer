"""
Extensive end-to-end use cases over the sample corpus.

- identification + hashing across every corpus file (crash-resistance, valid output)
- full analysis-pipeline verdicts for a representative single-file subset
- a spoofed-extension variation
- multi-file submission + incident correlation
- IP and domain IOC use cases (SSRF classification, punycode/homoglyph, domain intel)

Corpus-dependent tests skip when test-files/ is not reachable (e.g. running inside
the built image, where it is not mounted); they run in CI, which has the repo.
"""

import tempfile
from pathlib import Path

import pytest

from app.analyzers.identification import detect_file_type, calculate_hashes
from app.core.job_manager import job_manager

def _find_corpus() -> Path:
    # Resolve test-files/ whether the repo is laid out normally (CI copies the whole
    # repo) or the backend is mounted at /app (container test runs mount test-files there).
    for candidate in (
        Path(__file__).resolve().parents[2] / "test-files",
        Path("/app/test-files"),
        Path("test-files"),
    ):
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parents[2] / "test-files"


CORPUS_DIR = _find_corpus()
_SKIP_EXT = {".py", ".md"}
_SKIP_NAMES = {".DS_Store"}


def _corpus_files():
    if not CORPUS_DIR.is_dir():
        return []
    return sorted(
        p for p in CORPUS_DIR.iterdir()
        if p.is_file() and p.suffix.lower() not in _SKIP_EXT and p.name not in _SKIP_NAMES
    )


CORPUS_FILES = _corpus_files()
corpus_required = pytest.mark.skipif(not CORPUS_FILES, reason="test-files/ corpus not reachable")


def _run_pipeline(path: Path):
    job = job_manager.create_job(path.read_bytes(), path.name)
    try:
        return job_manager.execute_analysis_pipeline(job.job_id)
    finally:
        job_manager.delete_job(job.job_id)


# ---------------------------------------------------------------------------
# 1. Identification + hashing across the whole corpus (no crashes, valid output)
# ---------------------------------------------------------------------------

@corpus_required
@pytest.mark.parametrize("path", CORPUS_FILES, ids=[p.name for p in CORPUS_FILES])
def test_identify_and_hash_every_corpus_file(path):
    mime, category, desc = detect_file_type(path, path.name)
    assert isinstance(mime, str) and mime
    assert isinstance(category, str) and category
    assert isinstance(desc, str) and desc

    hashes = calculate_hashes(path)
    assert len(hashes["sha256"]) == 64
    assert len(hashes["md5"]) == 32


# ---------------------------------------------------------------------------
# 2. Full-pipeline verdicts for a representative single-file subset
# ---------------------------------------------------------------------------

# (filename, allowed risk levels) -- captured from real pipeline behaviour.
_SUBSET = [
    ("eicar_standard_av_test.txt", {"MALICIOUS"}),
    ("clean_image.png", {"CLEAN", "LOW RISK"}),
    ("clean_document.pdf", {"CLEAN", "LOW RISK"}),
    ("clean_office_document.docx", {"CLEAN", "LOW RISK", "MEDIUM RISK"}),
    ("active_content_xss.svg", {"HIGH RISK", "MALICIOUS"}),
    ("dangerous_archive_with_traversal.zip", {"HIGH RISK", "MALICIOUS"}),
    ("php_webshell_backdoor.php", {"HIGH RISK", "MALICIOUS"}),
    ("vbs_wscript_dropper.vbs", {"HIGH RISK", "MALICIOUS"}),
    ("powershell_cradle_amsi_bypass.ps1", {"HIGH RISK", "MALICIOUS"}),
]
_VALID_LEVELS = {"CLEAN", "LOW RISK", "MEDIUM RISK", "HIGH RISK", "MALICIOUS"}


@corpus_required
@pytest.mark.parametrize("name,allowed", _SUBSET, ids=[n for n, _ in _SUBSET])
def test_single_file_pipeline_verdict(name, allowed):
    path = CORPUS_DIR / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    job = _run_pipeline(path)
    assert job.state == "ANALYZED"
    assert job.risk is not None
    assert job.risk.level in _VALID_LEVELS
    assert job.risk.level in allowed, f"{name}: got {job.risk.level}, expected one of {allowed}"


# ---------------------------------------------------------------------------
# 3. Variation: a malicious payload hidden behind a spoofed extension
# ---------------------------------------------------------------------------

@corpus_required
def test_eicar_payload_with_spoofed_pdf_extension_still_malicious():
    eicar = CORPUS_DIR / "eicar_standard_av_test.txt"
    if not eicar.exists():
        pytest.skip("eicar sample missing")
    d = Path(tempfile.mkdtemp(prefix="fs_spoof_"))
    spoofed = d / "invoice.pdf"
    spoofed.write_bytes(eicar.read_bytes())
    job = _run_pipeline(spoofed)
    assert job.state == "ANALYZED"
    assert job.risk.level == "MALICIOUS"  # content, not extension, drives the verdict


# ---------------------------------------------------------------------------
# 4. Multi-file submission + incident correlation
# ---------------------------------------------------------------------------

@corpus_required
def test_multi_file_batch_and_correlation():
    from app.core.incident_correlator import IncidentCorrelator

    names = ["eicar_standard_av_test.txt", "php_webshell_backdoor.php", "active_content_xss.svg"]
    paths = [CORPUS_DIR / n for n in names if (CORPUS_DIR / n).exists()]
    if len(paths) < 2:
        pytest.skip("need at least two corpus samples for correlation")

    job_ids = []
    try:
        for p in paths:
            job = job_manager.create_job(p.read_bytes(), p.name)
            job_manager.execute_analysis_pipeline(job.job_id)
            job_ids.append(job.job_id)

        result = IncidentCorrelator.correlate_jobs(job_ids)
        assert result.get("success") is True
        assert result.get("total_jobs") == len(job_ids)
    finally:
        for jid in job_ids:
            job_manager.delete_job(jid)


# ---------------------------------------------------------------------------
# 5. IP IOC use cases: SSRF classification (pure, deterministic)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip,blocked", [
    ("127.0.0.1", True),
    ("::1", True),
    ("169.254.169.254", True),   # cloud metadata
    ("10.0.0.1", True),          # RFC1918
    ("172.16.0.1", True),
    ("192.168.1.100", True),
    ("8.8.8.8", False),          # public
    ("1.1.1.1", False),
])
def test_ip_ioc_ssrf_classification(ip, blocked):
    import ipaddress
    from app.network.ssrf import is_ip_blocked
    assert is_ip_blocked(ipaddress.ip_address(ip)) is blocked


@pytest.mark.parametrize("url", [
    "http://localhost:8080/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://10.0.0.5/internal",
])
def test_domain_ioc_ssrf_url_blocked(url):
    from app.network.ssrf import validate_url_for_ssrf
    is_safe, _reason, _ = validate_url_for_ssrf(url)
    assert is_safe is False


# ---------------------------------------------------------------------------
# 6. Domain IOC use cases: punycode / homoglyph + domain intel smoke
# ---------------------------------------------------------------------------

def test_domain_ioc_punycode_homoglyph():
    from app.analyzers.domain_analyzer import DomainAnalyzer
    # Plain ASCII domain: not punycode, not a homoglyph.
    plain = DomainAnalyzer.analyze_punycode("example.com")
    assert plain.get("is_punycode") is False
    # Cyrillic 'а' (U+0430) masquerading as Latin 'a'.
    homoglyph = DomainAnalyzer.analyze_punycode("аpple.com")
    assert homoglyph.get("is_homograph") is True


def test_domain_ioc_intel_smoke():
    # Passive domain intelligence on a reserved documentation domain, with active
    # subdomain recon disabled so the call stays bounded and does no scanning.
    from app.analyzers.domain_analyzer import DomainAnalyzer
    res = DomainAnalyzer.analyze("example.com", enable_subdomain_recon=False)
    assert isinstance(res, dict)
    assert res.get("target") or res.get("normalized") or res  # produced a result, no crash
