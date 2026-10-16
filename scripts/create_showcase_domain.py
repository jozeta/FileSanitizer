import json
from pathlib import Path

# Create master domain showcase file
target = "p\u0430ypal-security-update.com" # Cyrillic 'а'

showcase_data = {
    "target": target,
    "is_ip": False,
    "domain_info": {
        "target": target,
        "is_ip": False,
        "normalized_value": "xn--pypal-security-update-o7q.com",
        "whois": {
            "target": target,
            "registrar": "NameCheap, Inc.",
            "creation_date": "2026-09-15T12:00:00Z",
            "expiration_date": "2027-09-15T12:00:00Z",
            "domain_age_days": 31,
            "domain_age_formatted": "31 Days Old (Newly Registered)",
            "registrant_org": "Privacy Protect, LLC",
            "registrant_country": "PA",
            "nameservers": ["ns1.dns-cloud.org", "ns2.dns-cloud.org"],
            "dnssec": False,
            "status": ["clientTransferProhibited", "clientDeleteProhibited"]
        },
        "network": {
            "ip": "198.51.100.45",
            "reverse_dns": "edge-45.security-update.net",
            "asn": "AS13335",
            "as_org": "Cloudflare, Inc.",
            "country": "US",
            "city": "San Jose"
        },
        "fcrdns": {
            "ip": "198.51.100.45",
            "has_ptr": True,
            "ptr_hosts": ["edge-45.security-update.net"],
            "primary_ptr": "edge-45.security-update.net",
            "forward_ips": ["198.51.100.45"],
            "is_fcrdns_valid": True,
            "status": "VALID",
            "details": "Forward-Confirmed Reverse DNS verified: PTR edge-45.security-update.net resolves back to 198.51.100.45."
        },
        "dns_records": {
            "a": ["198.51.100.45", "198.51.100.46"],
            "aaaa": ["2001:db8::45"],
            "cname": ["unclaimed-bucket.s3.amazonaws.com"],
            "mx": [{"host": "mail.xn--pypal-security-update-o7q.com", "priority": 10}],
            "ns": ["ns1.dns-cloud.org", "ns2.dns-cloud.org"],
            "txt": ["v=spf1 include:_spf.google.com +all"],
            "soa": ["ns1.dns-cloud.org hostmaster.dns-cloud.org 2026101601 7200 3600 1209600 300"]
        },
        "advanced_dns": {
            "target": target,
            "is_ip": False,
            "records": {
                "a": ["198.51.100.45", "198.51.100.46"],
                "cname": ["unclaimed-bucket.s3.amazonaws.com"],
                "mx": [{"host": "mail.xn--pypal-security-update-o7q.com", "priority": 10}],
                "txt": ["v=spf1 include:_spf.google.com +all"]
            },
            "ttls": {"198.51.100.45": 60, "198.51.100.46": 60},
            "dnssec": {
                "enabled": False,
                "validated": False,
                "ds_records": [],
                "dnskey_count": 0,
                "notes": "Zone is unsigned and vulnerable to DNS spoofing."
            },
            "heuristics": {
                "has_wildcard_dns": True,
                "wildcard_ip": "198.51.100.45",
                "low_ttl_detected": True,
                "min_ttl": 60,
                "fast_flux_suspect": True,
                "dangling_cnames": [
                    {
                        "domain": f"assets.{target}",
                        "cname_target": "unclaimed-bucket.s3.amazonaws.com",
                        "provider": "AWS S3",
                        "status": "unclaimed_bucket",
                        "severity": "high",
                        "vulnerability": "Subdomain Takeover",
                        "description": "CNAME points to non-existent AWS S3 bucket returning NoSuchBucket"
                    },
                    {
                        "domain": f"portal.{target}",
                        "cname_target": "corpportal.surge.sh",
                        "provider": "Surge.sh",
                        "status": "unclaimed_surge_project",
                        "severity": "high",
                        "vulnerability": "Subdomain Takeover",
                        "description": "CNAME points to unclaimed Surge project"
                    }
                ]
            }
        },
        "attack_surface": {
            "root_domain": target,
            "total_discovered": 4,
            "active_count": 3,
            "dormant_count": 1,
            "subdomains": [
                {
                    "subdomain": f"assets.{target}",
                    "status": "active",
                    "cname": "unclaimed-bucket.s3.amazonaws.com",
                    "ips": ["52.216.100.1"],
                    "is_root": False,
                    "discovered_from": "Certificate Transparency"
                },
                {
                    "subdomain": f"portal.{target}",
                    "status": "active",
                    "cname": "corpportal.surge.sh",
                    "ips": ["138.197.235.123"],
                    "is_root": False,
                    "discovered_from": "Subdomain Enumeration"
                },
                {
                    "subdomain": f"api.{target}",
                    "status": "active",
                    "cname": "",
                    "ips": ["198.51.100.45"],
                    "is_root": False,
                    "discovered_from": "DNS Brute Force"
                }
            ]
        },
        "email_security": {
            "domain": target,
            "dmarc": {
                "present": True,
                "raw_record": "v=DMARC1; p=none; sp=none; pct=100; rua=mailto:dmarc@security-update.net",
                "policy": "none",
                "subdomain_policy": "none",
                "percentage": 100,
                "aggregate_reports": ["mailto:dmarc@security-update.net"],
                "forensic_reports": [],
                "adkim": "r",
                "aspf": "r",
                "is_enforced": False
            },
            "dkim": {
                "selectors_checked": 8,
                "selectors_found": []
            },
            "bimi": {
                "present": False,
                "has_vmc": False
            },
            "spoofability": {
                "status": "VULNERABLE",
                "risk_score": 85,
                "summary": "Domain is vulnerable to direct sender spoofing: DMARC policy is set to 'p=none' (audit mode) and SPF contains '+all' permissive authorization.",
                "remediations": [
                    "Change DMARC policy from 'p=none' to 'p=reject' to block spoofed messages.",
                    "Update SPF record from '+all' to '-all' (HardFail) or '~all' (SoftFail).",
                    "Publish 2048-bit DKIM cryptographic keys for outgoing mail servers."
                ]
            }
        },
        "tls_profile": {
            "target": target,
            "port": 443,
            "has_tls": True,
            "live_cert": {
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "cipher_bits": 256,
                "subject": {"common_name": f"*.{target}", "organization": "Security Update LLC", "country": "US"},
                "issuer": {"common_name": "Let's Encrypt Authority X3", "organization": "Let's Encrypt", "country": "US"},
                "sans": [target, f"*.{target}", f"api.{target}", f"assets.{target}"],
                "sha256_fingerprint": "7c:9a:12:4b:8e:23:fa:56:d1:09:88:fe:34:ab:67:12:90:bc:cd:ef:12:34:56:78:9a:bc:de:f0:12:34:56:78",
                "serial_number": "03:FA:98:B1:77:22:90:01:A4:CC",
                "not_before": "2026-09-15T00:00:00",
                "not_after": "2026-10-21T23:59:59",
                "days_remaining": 5,
                "is_expired": False,
                "is_self_signed": False
            },
            "ct_logs": {
                "queried": True,
                "total_certificates_found": 3,
                "discovered_subdomains": [f"api.{target}", f"assets.{target}", f"portal.{target}"],
                "issuers": ["Let's Encrypt"]
            },
            "cipher_suites_audit": {
                "active_cipher": "TLS_AES_256_GCM_SHA384",
                "active_protocol": "TLSv1.3",
                "total_cataloged": 6,
                "supported_count": 4,
                "weak_ciphers_count": 2,
                "has_weak_ciphers": True,
                "weak_ciphers": [
                    {
                        "name": "DES-CBC3-SHA",
                        "protocol": "TLSv1.0/1.2",
                        "key_exchange": "RSA (Static)",
                        "encryption": "3DES-EDE-CBC",
                        "mac": "SHA1",
                        "bits": 112,
                        "status": "INSECURE",
                        "is_weak": True,
                        "supported": True,
                        "active_negotiated": False,
                        "explanation": "Sweet32 Vulnerability (CVE-2016-2183): 64-bit block size allows collision attacks in long TLS sessions, allowing attackers to recover sensitive authentication cookies."
                    },
                    {
                        "name": "RC4-SHA",
                        "protocol": "TLSv1.0",
                        "key_exchange": "RSA (Static)",
                        "encryption": "RC4-128",
                        "mac": "SHA1",
                        "bits": 128,
                        "status": "BROKEN",
                        "is_weak": True,
                        "supported": True,
                        "active_negotiated": False,
                        "explanation": "Bar Mitzvah / RC4 NOMORE Attacks: Severe statistical biases in the RC4 keystream allow practical plaintext recovery and session cookie extraction. Strictly prohibited by RFC 7465."
                    }
                ],
                "ciphers": [
                    {
                        "name": "TLS_AES_256_GCM_SHA384",
                        "protocol": "TLSv1.3",
                        "key_exchange": "ECDHE (PFS)",
                        "encryption": "AES-256-GCM",
                        "mac": "AEAD",
                        "bits": 256,
                        "status": "RECOMMENDED",
                        "is_weak": False,
                        "supported": True,
                        "active_negotiated": True,
                        "explanation": "Modern authenticated encryption (AEAD) with Perfect Forward Secrecy. Top-tier cryptographic security (NIST SP 800-52r2)."
                    },
                    {
                        "name": "ECDHE-RSA-AES256-GCM-SHA384",
                        "protocol": "TLSv1.2",
                        "key_exchange": "ECDHE (PFS)",
                        "encryption": "AES-256-GCM",
                        "mac": "AEAD",
                        "bits": 256,
                        "status": "RECOMMENDED",
                        "is_weak": False,
                        "supported": True,
                        "active_negotiated": False,
                        "explanation": "Elliptic curve Ephemeral Diffie-Hellman with RSA signature and AES-256-GCM authenticated encryption."
                    },
                    {
                        "name": "DES-CBC3-SHA",
                        "protocol": "TLSv1.0/1.2",
                        "key_exchange": "RSA (Static)",
                        "encryption": "3DES-EDE-CBC",
                        "mac": "SHA1",
                        "bits": 112,
                        "status": "INSECURE",
                        "is_weak": True,
                        "supported": True,
                        "active_negotiated": False,
                        "explanation": "Sweet32 Vulnerability (CVE-2016-2183): 64-bit block size allows collision attacks in long TLS sessions, allowing attackers to recover sensitive authentication cookies."
                    },
                    {
                        "name": "RC4-SHA",
                        "protocol": "TLSv1.0",
                        "key_exchange": "RSA (Static)",
                        "encryption": "RC4-128",
                        "mac": "SHA1",
                        "bits": 128,
                        "status": "BROKEN",
                        "is_weak": True,
                        "supported": True,
                        "active_negotiated": False,
                        "explanation": "Bar Mitzvah / RC4 NOMORE Attacks: Severe statistical biases in the RC4 keystream allow practical plaintext recovery and session cookie extraction. Strictly prohibited by RFC 7465."
                    }
                ]
            }
        },
        "web_fingerprint": {
            "initial_url": f"http://{target}",
            "final_url": f"https://{target}/login",
            "status_code": 200,
            "hop_count": 1,
            "redirect_chain": [
                {"hop": 1, "url": f"http://{target}", "status_code": 301, "location": f"https://{target}/login"},
                {"hop": 2, "url": f"https://{target}/login", "status_code": 200}
            ],
            "server_technology": "Apache/2.4.41 (Ubuntu)",
            "security_headers": {
                "grade": "F",
                "score": 15,
                "hsts": {"present": False},
                "csp": {"present": False},
                "x_frame_options": {"present": False},
                "x_content_type_options": {"present": False},
                "recommendations": ["Configure Strict-Transport-Security (HSTS)", "Deploy Content-Security-Policy (CSP)"]
            }
        },
        "threat_intelligence": {
            "indicator": target,
            "indicator_type": "domain",
            "overall_verdict": "suspicious",
            "malicious_votes": 3,
            "threat_tags": ["homoglyph-impersonation", "brand-spoofing", "dangling-cname"],
            "feeds": {
                "virustotal": {"queried": True, "verdict": "suspicious", "detections": 3, "total": 89},
                "urlhaus": {"queried": True, "verdict": "clean", "url_count": 0},
                "abuseipdb": {"queried": True, "verdict": "suspicious", "abuse_confidence_score": 45, "total_reports": 12}
            }
        },
        "risk_scores": {
            "maliciousness": {"score": 82, "level": "critical", "factors": [{"weight": 40, "title": "Cyrillic Homoglyph Impersonation", "description": "Character 'а' is Cyrillic lookalike for 'a' targeting PayPal brand."}]},
            "infrastructure_risk": {"score": 78, "level": "high", "factors": [{"weight": 35, "title": "Subdomain Takeover Vulnerability", "description": "Dangling CNAMEs pointing to unclaimed AWS S3 and Surge cloud endpoints."}]},
            "exposure": {"score": 75, "level": "high", "factors": [{"weight": 25, "title": "Permissive Email Security", "description": "DMARC p=none policy combined with SPF +all enables spoofing."}]},
            "attribution_confidence": {"score": 90, "level": "high", "factors": [{"weight": 30, "title": "Clear Technical Footprint", "description": "Correlated nameservers and infrastructure telemetry confirm assessment."}]}
        }
    }
}

out_path = Path("/Users/zeta/Desktop/code/FileSanitizer/test-files/demo_showcase/checklist_master_target.domain")
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(showcase_data, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Generated {out_path} ({out_path.stat().st_size} bytes)")

# Create second demo file demonstrating Hostname Mismatch (RFC 6125 depth boundary violation)
import copy
mismatch_data = copy.deepcopy(showcase_data)
mismatch_target = "deep.internal.api.banking-secure.org"
mismatch_data["target"] = mismatch_target
mismatch_data["domain_info"]["target"] = mismatch_target
mismatch_data["domain_info"]["tls_profile"]["live_cert"]["subject"]["common_name"] = "*.banking-secure.org"
mismatch_data["domain_info"]["tls_profile"]["live_cert"]["sans"] = ["*.banking-secure.org", "banking-secure.org"]

mismatch_path = Path("/Users/zeta/Desktop/code/FileSanitizer/test-files/demo_showcase/hostname_mismatch_target.domain")
mismatch_path.write_text(json.dumps(mismatch_data, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Generated {mismatch_path} ({mismatch_path.stat().st_size} bytes)")

