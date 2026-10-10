import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app
from app.network.url_fetcher import URLFileFetcher, URLFetcherException

client = TestClient(app)

def test_fetch_url_ssrf_blocking_localhost():
    """Verify that localhost and loopback URLs are blocked immediately."""
    with pytest.raises(URLFetcherException) as exc_info:
        URLFileFetcher.fetch("http://localhost:8000/secret.pdf")
    assert "SSRF" in exc_info.value.message or "Forbidden local destination" in exc_info.value.message

def test_fetch_url_ssrf_blocking_private_ip():
    """Verify that private RFC 1918 subnets are blocked."""
    with pytest.raises(URLFetcherException) as exc_info:
        URLFileFetcher.fetch("http://192.168.1.50/invoice.pdf")
    assert "SSRF" in exc_info.value.message

def test_fetch_url_ssrf_blocking_cloud_metadata():
    """Verify that 169.254.169.254 is blocked."""
    with pytest.raises(URLFetcherException) as exc_info:
        URLFileFetcher.fetch("http://169.254.169.254/latest/meta-data")
    assert "SSRF" in exc_info.value.message

def test_fetch_url_reputation_malicious_rejection():
    """Verify that a URL flagged as MALICIOUS by reputation is NOT blocked, but findings are recorded."""
    with patch("app.network.url_fetcher.validate_url_for_ssrf", return_value=(True, None, ["93.184.216.34"])):
        with patch("app.network.url_fetcher.URLAnalyzer.analyze_url", return_value={
            "risk": "MALICIOUS",
            "indicators": ["URLhaus active malware distribution list"]
        }):
            fake_pdf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/pdf", "content-disposition": 'filename="payload.pdf"'}
            mock_resp.iter_bytes.return_value = [fake_pdf]
            mock_client = MagicMock()
            mock_client.stream.return_value.__enter__.return_value = mock_resp
            with patch("httpx.Client") as mock_httpx:
                mock_httpx.return_value.__enter__.return_value = mock_client
                res = URLFileFetcher.fetch("https://malicious-distributor.xyz/payload.pdf")
                assert res.reputation.get("risk") == "MALICIOUS"

def test_fetch_url_unsupported_format_rejection():
    """Verify that an unsupported file format (e.g. MP3 audio) is rejected."""
    fake_audio_bytes = b"ID3\x03\x00\x00\x00\x00\x00" + b"\x00" * 200

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "audio/mpeg", "content-disposition": 'filename="sample.mp3"'}
    mock_resp.iter_bytes.return_value = [fake_audio_bytes]

    mock_client = MagicMock()
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("app.network.url_fetcher.validate_url_for_ssrf", return_value=(True, None, ["93.184.216.34"])):
        with patch("app.network.url_fetcher.URLAnalyzer.analyze_url", return_value={"risk": "CLEAN", "indicators": []}):
            with patch("httpx.Client") as mock_httpx:
                mock_httpx.return_value.__enter__.return_value = mock_client
                with pytest.raises(URLFetcherException) as exc_info:
                    URLFileFetcher.fetch("https://example.com/sample.mp3")
                assert "Unsupported file format" in exc_info.value.message

def test_fetch_url_api_endpoint_success():
    """Verify POST /api/files/fetch-url creates a job for a valid PDF download."""
    fake_pdf = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "application/pdf", "content-disposition": 'filename="sample_advisory.pdf"'}
    mock_resp.iter_bytes.return_value = [fake_pdf]

    mock_client = MagicMock()
    mock_client.stream.return_value.__enter__.return_value = mock_resp

    with patch("app.network.url_fetcher.validate_url_for_ssrf", return_value=(True, None, ["93.184.216.34"])):
        with patch("app.network.url_fetcher.URLAnalyzer.analyze_url", return_value={
            "url": "https://example.com/sample_advisory.pdf",
            "domain": "example.com",
            "risk": "CLEAN",
            "indicators": []
        }):
            with patch("httpx.Client") as mock_httpx:
                mock_httpx.return_value.__enter__.return_value = mock_client
                res = client.post("/api/files/fetch-url", json={"url": "https://example.com/sample_advisory.pdf"})
                assert res.status_code == 200
                data = res.json()
                assert data["uploaded"] == 1
                assert len(data["jobs"]) == 1
                assert "sample_advisory" in data["jobs"][0]["filename"]

def test_get_supported_formats_endpoint():
    """Verify GET /api/files/supported-formats returns the complete catalog."""
    res = client.get("/api/files/supported-formats")
    assert res.status_code == 200
    data = res.json()
    assert "categories" in data
    assert data["total_categories"] >= 6
    categories = [c["category"] for c in data["categories"]]
    assert "Images" in categories
    assert "PDF Documents" in categories
    assert "Microsoft Office Documents" in categories
    assert "Archives" in categories
