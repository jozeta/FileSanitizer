import pytest
from app.analyzers.ip_domain_forensics import (
    normalize_and_classify_indicator,
    analyze_dns_configuration,
    analyze_subdomain_takeover_risk,
    analyze_email_domain_posture,
    analyze_tls_cert_forensics,
    validate_hostname_match,
    analyze_web_headers_and_exposure,
    calculate_ip_domain_executive_verdict,
    generate_ip_domain_offline_tools_guide
)


def test_indicator_normalisation_ipv4_and_ipv6():
    # 1. IPv4
    res_v4 = normalize_and_classify_indicator("  198.51.100.1  ")
    assert res_v4["is_valid"] is True
    assert res_v4["indicator_type"] == "ipv4"
    assert res_v4["normalized_value"] == "198.51.100.1"

    # 2. IPv6 compressed representation
    res_v6 = normalize_and_classify_indicator("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert res_v6["is_valid"] is True
    assert res_v6["indicator_type"] == "ipv6"
    assert res_v6["normalized_value"] == "2001:db8::1"

    # 3. IPv4-mapped IPv6
    res_mapped = normalize_and_classify_indicator("::ffff:192.0.2.128")
    assert res_mapped["is_valid"] is True
    assert res_mapped["is_ipv4_mapped_ipv6"] is True
    assert res_mapped["mapped_ipv4"] == "192.0.2.128"


def test_public_vs_private_ip_classification():
    # Private RFC 1918
    res_priv = normalize_and_classify_indicator("10.50.25.1")
    assert res_priv["is_private_rfc1918"] is True
    assert res_priv["ip_classification"] == "RFC 1918 Private"
    assert res_priv["rdns_eligible"] is False

    # Loopback
    res_loop = normalize_and_classify_indicator("127.0.0.1")
    assert res_loop["is_loopback"] is True
    assert res_loop["ip_classification"] == "Loopback"
    assert res_loop["rdns_eligible"] is False

    # Link-Local
    res_ll = normalize_and_classify_indicator("169.254.169.254")
    assert res_ll["is_link_local"] is True
    assert res_ll["ip_classification"] == "Link-Local"
    assert res_ll["rdns_eligible"] is False

    # Carrier-Grade NAT (CGNAT)
    res_cgnat = normalize_and_classify_indicator("100.64.10.5")
    assert res_cgnat["ip_classification"] == "Carrier-Grade NAT (CGNAT / RFC 6598)"
    assert res_cgnat["rdns_eligible"] is False

    # Public Internet IP
    res_pub = normalize_and_classify_indicator("8.8.8.8")
    assert res_pub["is_public_internet"] is True
    assert res_pub["ip_classification"] == "Public Internet"
    assert res_pub["rdns_eligible"] is True


def test_domain_normalisation_and_public_suffix():
    # Trailing dot and uppercase stripping
    res_dom = normalize_and_classify_indicator("  EXAMPLE.COM.  ")
    assert res_dom["normalized_value"] == "example.com"
    assert res_dom["indicator_type"] == "domain"
    assert res_dom["registrable_domain"] == "example.com"
    assert res_dom["public_suffix"] == "com"

    # Multi-part ccTLD (e.g. co.uk)
    res_uk = normalize_and_classify_indicator("api.portal.service.co.uk")
    assert res_uk["subdomain"] == "api.portal"
    assert res_uk["registrable_domain"] == "service.co.uk"
    assert res_uk["public_suffix"] == "co.uk"


def test_punycode_and_homoglyphs():
    # Cyrillic lookalike 'о' (U+043E) in 'microsоft.com'
    cyrillic_target = "micros\u043Eft.com"
    res_homo = normalize_and_classify_indicator(cyrillic_target)
    assert res_homo["has_homoglyphs"] is True
    assert len(res_homo["homoglyphs"]) > 0
    assert res_homo["homoglyphs"][0]["lookalike"] == "o"


def test_special_use_internal_domains():
    res_internal = normalize_and_classify_indicator("database-cluster.local")
    assert res_internal["is_special_use_domain"] is True
    assert "reserved" in res_internal["special_use_reason"].lower()

    res_onion = normalize_and_classify_indicator("darkmarket.onion")
    assert res_onion["is_special_use_domain"] is True


def test_dns_sec_and_configuration_audit():
    mock_domain_info = {
        "advanced_dns": {
            "records": {
                "a": ["1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7", "1.2.3.8"],
                "aaaa": ["::1"],
                "mx": [{"host": "mail.example.com", "priority": 10}],
                "ns": ["ns1.example.com", "ns2.example.com"],
                "txt": ["v=spf1 include:_spf.google.com ~all"],
                "cname": [],
                "soa": [{"serial": 2026101601}],
                "caa": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
                "ptr": []
            },
            "ttls": {"a": 60, "mx": 300},
            "dnssec": {
                "enabled": True,
                "validated": True,
                "ds_records": [{"key_tag": 12345, "algorithm": 13, "digest_type": 2, "digest": "abcdef"}]
            },
            "heuristics": {
                "has_wildcard_dns": True,
                "wildcard_ip": "1.2.3.4",
                "low_ttl_detected": True,
                "fast_flux_suspect": True
            }
        }
    }
    audit = analyze_dns_configuration(mock_domain_info)
    assert audit["dnssec"]["is_validated"] is True
    assert "Secure / Validated" in audit["dnssec"]["status"]
    assert audit["ttl_analysis"]["fast_flux_suspect"] is True
    assert audit["wildcard_dns"]["detected"] is True
    assert audit["has_caa"] is True


def test_subdomain_takeover_detection():
    mock_domain_info = {
        "target": "vulnerable-corp.com",
        "advanced_dns": {
            "records": {
                "cname": ["orphaned-assets.s3.amazonaws.com"]
            }
        },
        "attack_surface": {
            "subdomains": [
                {"subdomain": "blog.vulnerable-corp.com", "cname": "old-blog.github.io"},
                {"subdomain": "app.vulnerable-corp.com", "cname": "dead-app.herokuapp.com"}
            ]
        }
    }
    takeover = analyze_subdomain_takeover_risk(mock_domain_info)
    assert takeover["has_takeover_risk"] is True
    assert takeover["claimable_count"] == 3
    providers = [d["service_provider"] for d in takeover["dangling_cnames"]]
    assert "AWS S3" in providers
    assert "GitHub Pages" in providers
    assert "Heroku" in providers
    assert len(takeover["remediation_guidance"]) > 0


def test_email_domain_posture_and_spoofability():
    # Vulnerable domain (missing DMARC, permissive SPF)
    mock_vuln = {
        "email_security": {
            "spf": {"raw": "v=spf1 +all"},
            "dmarc": {"raw": "v=DMARC1; p=none", "policy": "none"}
        },
        "advanced_dns": {
            "records": {
                "mx": [{"host": "mail.example.com", "priority": 10}]
            }
        }
    }
    posture_vuln = analyze_email_domain_posture(mock_vuln)
    assert posture_vuln["is_spoofable"] is True
    assert posture_vuln["spf"]["is_permissive"] is True
    assert posture_vuln["dmarc"]["vulnerable_to_spoofing"] is True

    # Robust domain (strict SPF -all and DMARC reject)
    mock_secure = {
        "email_security": {
            "spf": {"raw": "v=spf1 include:_spf.google.com -all"},
            "dmarc": {"raw": "v=DMARC1; p=reject; rua=mailto:dmarc@secure.com", "policy": "reject"}
        },
        "advanced_dns": {
            "records": {
                "mx": [{"host": "aspmx.l.google.com", "priority": 1}]
            }
        }
    }
    posture_sec = analyze_email_domain_posture(mock_secure)
    assert posture_sec["is_spoofable"] is False
    assert posture_sec["dmarc"]["is_enforced"] is True


def test_tls_cert_forensics():
    mock_domain = {
        "target": "secure.example.com",
        "tls_profile": {
            "live_cert": {
                "subject_cn": "secure.example.com",
                "issuer_o": "Let's Encrypt",
                "sans": ["secure.example.com", "www.example.com"],
                "days_to_expiry": 45,
                "is_expired": False,
                "is_self_signed": False,
                "signature_algorithm": "sha256WithRSAEncryption",
                "key_type": "RSA",
                "key_size": 2048
            },
            "ct_logs": {
                "total_certificates_found": 12
            }
        }
    }
    tls_audit = analyze_tls_cert_forensics(mock_domain)
    assert tls_audit["hostname_matches_cert"] is True
    assert tls_audit["days_to_expiry"] == 45
    assert tls_audit["is_expired"] is False
    assert tls_audit["ct_logs_count"] == 12


def test_web_security_headers_and_exposure():
    mock_domain = {
        "web_fingerprint": {
            "server": "nginx/1.22.1",
            "security_headers": {
                "hsts": True,
                "csp": False
            },
            "headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains"
            }
        },
        "web_exposure": {
            "discovered_files": [
                {"path": "/.env", "status": 200, "description": "Environment Configuration File Leak"}
            ]
        }
    }
    web_audit = analyze_web_headers_and_exposure(mock_domain)
    assert web_audit["headers"]["hsts"] is True
    assert "Content-Security-Policy (CSP)" in web_audit["missing_headers"]
    assert "nginx" in web_audit["server_banner"].lower()
    assert len(web_audit["exposed_sensitive_files"]) == 1


def test_executive_verdict_and_offline_cli_guide():
    normal = normalize_and_classify_indicator("malicious-c2-node.com")
    dns_aud = {"ttl_analysis": {"fast_flux_suspect": True}}
    takeover = {"has_takeover_risk": True, "claimable_count": 1}
    email_p = {"is_spoofable": True}
    tls_aud = {"is_expired": False, "hostname_matches_cert": True}
    web_aud = {"missing_headers": ["HSTS"]}

    mock_info = {
        "target": "malicious-c2-node.com",
        "is_ip": False,
        "threat_intelligence": {
            "overall_verdict": "malicious",
            "consensus_score": 95,
            "threat_tags": ["CobaltStrike C2", "Phishing"]
        },
        "risk_flags": [
            {"severity": "critical", "title": "C2 Infrastructure", "description": "Cobalt Strike team server"}
        ]
    }

    verdict = calculate_ip_domain_executive_verdict(
        mock_info, normal, dns_aud, takeover, email_p, tls_aud, web_aud
    )
    assert verdict["verdict"] == "Malicious"
    assert verdict["severity"] == "Critical"
    assert verdict["confidence_score"] >= 90
    assert "T1566.002" in verdict["mitre_attack"]
    assert len(verdict["containment_checklist"]) > 0

    # Offline CLI guide
    guide = generate_ip_domain_offline_tools_guide("malicious-c2-node.com", False, "1.2.3.4")
    assert len(guide["tools"]) == 6
    tool_names = [t["tool"] for t in guide["tools"]]
    assert any("dig" in n for n in tool_names)
    assert any("rdap" in n for n in tool_names)
    assert any("openssl" in n for n in tool_names)
    assert any("curl" in n for n in tool_names)
    assert any("nmap" in n for n in tool_names)
    assert any("ipaddress" in n for n in tool_names)


def test_benign_domain_verdict_and_breakdown():
    normal = normalize_and_classify_indicator("google.com")
    dns_aud = {"ttl_analysis": {"fast_flux_suspect": False, "low_ttl_detected": True, "min_ttl_seconds": 60}}
    takeover = {"has_takeover_risk": False}
    email_p = {"is_spoofable": False, "dmarc_policy": "reject"}
    tls_aud = {"is_expired": False, "status": "valid", "issuer_org": "Google Trust Services"}
    web_aud = {"missing_headers": []}

    mock_clean = {
        "target": "google.com",
        "is_ip": False,
        "threat_intelligence": {
            "overall_verdict": "clean",
            "consensus_score": 0,
            "threat_tags": []
        },
        "whois": {
            "domain_age_days": 10000,
            "registration_date": "1997-09-15"
        },
        "asn_profile": {
            "is_bulletproof_suspect": False,
            "as_org": "Google LLC"
        },
        "risk_flags": []
    }

    verdict = calculate_ip_domain_executive_verdict(
        mock_clean, normal, dns_aud, takeover, email_p, tls_aud, web_aud
    )
    assert verdict["verdict"] == "Clean / Benign"
    assert verdict["severity"] == "Clean"
    assert verdict["risk_score"] <= 15
    assert "risk_breakdown" in verdict
    breakdown = verdict["risk_breakdown"]
    assert "threat_intelligence" in breakdown
    assert "infrastructure_reputation" in breakdown
    assert "cryptographic_trust" in breakdown
    assert "exposure_and_hardening" in breakdown
    assert breakdown["threat_intelligence"]["score"] == 0


def test_validate_hostname_match():
    # 1. Exact SAN match
    res_exact = validate_hostname_match("api.example.com", "example.com", ["api.example.com", "example.com"])
    assert res_exact["matches"] is True
    assert res_exact["match_type"] == "EXACT_SAN"
    assert "Exact match" in res_exact["how"]
    assert "RFC 6125 §6.4.1" in res_exact["why"]

    # 2. Wildcard SAN match
    res_wc = validate_hostname_match("portal.example.com", "example.com", ["*.example.com"])
    assert res_wc["matches"] is True
    assert res_wc["match_type"] == "WILDCARD_SAN"
    assert "Wildcard match" in res_wc["how"]

    # 3. Wildcard Depth Exceeded (e.g. deep.sub.example.com vs *.example.com)
    res_wc_deep = validate_hostname_match("deep.sub.example.com", "example.com", ["*.example.com"])
    assert res_wc_deep["matches"] is False
    assert res_wc_deep["mismatch_type"] == "WILDCARD_DEPTH_EXCEEDED"
    assert "Wildcard boundary violation" in res_wc_deep["how"]
    assert "RFC 6125 §6.4.3" in res_wc_deep["why"]

    # 4. IP without iPAddress SAN
    res_ip_mismatch = validate_hostname_match("198.51.100.1", "example.com", ["example.com", "www.example.com"], is_ip=True)
    assert res_ip_mismatch["matches"] is False
    assert res_ip_mismatch["mismatch_type"] == "IP_WITHOUT_IP_SAN"
    assert "RFC 5280 §4.2.1.6" in res_ip_mismatch["why"]

    # 5. CDN SNI fallback
    res_cdn = validate_hostname_match("victim.org", "ssl123.cloudflare.com", ["*.cloudflare.com"], issuer_o="Cloudflare, Inc.")
    assert res_cdn["matches"] is False
    assert res_cdn["mismatch_type"] == "CDN_SNI_MISCONFIGURATION"
    assert "Edge CDN" in res_cdn["why"]


def test_supported_ciphers_audit():
    from app.network.tls_inspector import CIPHER_SECURITY_CATALOG, TLSInspector

    # Verify catalog contains required legacy and modern ciphers
    assert "TLS_AES_256_GCM_SHA384" in CIPHER_SECURITY_CATALOG
    assert "DES-CBC3-SHA" in CIPHER_SECURITY_CATALOG
    assert "RC4-SHA" in CIPHER_SECURITY_CATALOG

    # Verify Sweet32 explanation
    des_info = CIPHER_SECURITY_CATALOG["DES-CBC3-SHA"]
    assert des_info["is_weak"] is True
    assert des_info["status"] == "INSECURE"
    assert "Sweet32" in des_info["explanation"]

    # Verify RC4 explanation
    rc4_info = CIPHER_SECURITY_CATALOG["RC4-SHA"]
    assert rc4_info["is_weak"] is True
    assert rc4_info["status"] == "BROKEN"
    assert "Bar Mitzvah" in rc4_info["explanation"] or "RFC 7465" in rc4_info["explanation"]

    # Test audit method
    audit = TLSInspector._audit_supported_ciphers("example.com", 443, "ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.3")
    assert audit["total_cataloged"] > 0
    assert audit["active_cipher"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert any(c["active_negotiated"] for c in audit["ciphers"])

