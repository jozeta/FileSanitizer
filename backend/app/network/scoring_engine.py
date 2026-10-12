"""
Multi-Dimensional Risk & Exposure Scoring Engine.
Computes 4 distinct, transparent risk dimensions:
1. Maliciousness Score (threat feed detections, CTI consensus, malware campaigns, homographs)
2. Infrastructure Risk (newly registered domains, fast-flux DNS, bulletproof ASNs, dangling CNAMEs)
3. Exposure Score (security headers compliance, deprecated TLS, open management ports, SPF posture)
4. Attribution Confidence (confirmed cryptographic SAN links, distinctive NS, tracking IDs vs. shared IP)
"""

from typing import Dict, Any, List, Optional, Tuple


class MultiDimensionalRiskEngine:
    """
    Evaluates evidence across all intelligence modules to produce transparent, multi-axis risk ratings.
    """

    @classmethod
    def evaluate(
        cls,
        target: str,
        is_ip: bool,
        normalizer_details: Dict[str, Any],
        dns_data: Dict[str, Any],
        whois_data: Dict[str, Any],
        tls_data: Dict[str, Any],
        web_data: Dict[str, Any],
        cti_data: Dict[str, Any],
        asn_profile: Dict[str, Any],
        active_scan: Optional[Dict[str, Any]] = None,
        email_sec: Optional[Dict[str, Any]] = None,
        web_arch: Optional[Dict[str, Any]] = None,
        active_probes: Optional[Dict[str, Any]] = None,
        vuln_intel: Optional[Dict[str, Any]] = None,
        web_exposure: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes all intelligence into 4 dimension scores with detailed contributing factors.
        """
        # 1. Maliciousness Dimension
        mal_score, mal_factors = cls._calculate_maliciousness(normalizer_details, cti_data)

        # 2. Infrastructure Risk Dimension
        infra_score, infra_factors = cls._calculate_infrastructure_risk(whois_data, dns_data, asn_profile, web_arch)

        # 3. Exposure Dimension
        exp_score, exp_factors = cls._calculate_exposure(tls_data, web_data, dns_data, active_scan, email_sec, active_probes, vuln_intel, web_exposure)

        # 4. Attribution Confidence Dimension
        attr_score, attr_factors = cls._calculate_attribution_confidence(tls_data, dns_data, whois_data, web_data)

        return {
            "maliciousness": {
                "score": mal_score,
                "level": cls._score_to_level(mal_score),
                "factors": mal_factors
            },
            "infrastructure_risk": {
                "score": infra_score,
                "level": cls._score_to_level(infra_score),
                "factors": infra_factors
            },
            "exposure": {
                "score": exp_score,
                "level": cls._score_to_level(exp_score),
                "factors": exp_factors
            },
            "attribution_confidence": {
                "score": attr_score,
                "level": cls._score_to_level(attr_score),
                "factors": attr_factors
            },
            "overall_risk": {
                "score": max(mal_score, int(infra_score * 0.8), int(exp_score * 0.6)),
                "level": cls._score_to_level(max(mal_score, int(infra_score * 0.8), int(exp_score * 0.6)))
            }
        }

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 15:
            return "low"
        return "clean"

    @classmethod
    def _calculate_maliciousness(cls, normalizer: Dict[str, Any], cti: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        score = 0
        factors = []

        # Homograph attack
        homo = normalizer.get("homoglyph_analysis", {})
        if homo.get("is_homograph") or homo.get("is_confusable"):
            score += 50
            factors.append({
                "weight": 50,
                "title": "Homoglyph Impersonation Attack",
                "description": f"Domain visually masquerades as '{homo.get('unicode_rendered')}' using lookalike glyphs."
            })

        # Obfuscation (dword, hex, octal, userinfo spoofing)
        obf = normalizer.get("obfuscation", {})
        if obf.get("is_obfuscated"):
            score += 35
            factors.append({
                "weight": 35,
                "title": "URL / IP Obfuscation Detected",
                "description": "Uses non-standard numerical or credential delimiters to evade filters."
            })

        # CTI consensus
        mal_votes = cti.get("malicious_votes", 0)
        if mal_votes >= 3:
            score += 60
            factors.append({
                "weight": 60,
                "title": f"Consensus CTI Detections ({mal_votes} Feeds)",
                "description": "Target is identified as malicious by multiple threat feeds (VirusTotal, URLhaus, ThreatFox)."
            })
        elif mal_votes >= 1:
            score += 30
            factors.append({
                "weight": 30,
                "title": "Threat Intelligence Detection",
                "description": "Target was flagged as suspicious or malicious in at least one reputation feed."
            })

        # Malware families identified
        families = cti.get("malware_families", [])
        if families:
            score += 25
            factors.append({
                "weight": 25,
                "title": f"Associated Malware: {', '.join(families[:3])}",
                "description": "Known malware or C2 communications linked to this indicator."
            })

        return min(100, score), factors

    @classmethod
    def _calculate_infrastructure_risk(cls, whois: Dict[str, Any], dns: Dict[str, Any], asn: Dict[str, Any], web_arch: Optional[Dict[str, Any]] = None) -> Tuple[int, List[Dict[str, Any]]]:
        score = 0
        factors = []

        # Domain age
        age = whois.get("domain_age_days")
        if age is not None:
            if age < 7:
                score += 50
                factors.append({
                    "weight": 50,
                    "title": f"Brand New Domain ({age} Days Old)",
                    "description": "Registered less than 7 days ago. Extremely high correlation with phishing and disposable campaigns."
                })
            elif age < 30:
                score += 30
                factors.append({
                    "weight": 30,
                    "title": f"Newly Registered Domain ({age} Days Old)",
                    "description": "Registered within the last 30 days."
                })

        # Dormant Revival / Dropped Domain Hijacking
        if web_arch and web_arch.get("dormant_revival_detected"):
            score += 35
            gap = web_arch.get("revival_gap_days", 730) // 365
            factors.append({
                "weight": 35,
                "title": f"Dormant Domain Revival ({gap}+ Year Inactivity Gap)",
                "description": "Domain experienced a multi-year gap before recent activity, characteristic of expired domain repurposing."
            })

        # Dangling CNAME / Subdomain takeover candidate
        takeovers = dns.get("heuristics", {}).get("dangling_cnames", [])
        if takeovers:
            score += 45
            factors.append({
                "weight": 45,
                "title": f"Dangling CNAME ({takeovers[0].get('provider', 'Cloud')})",
                "description": "CNAME points to an unallocated or unresolving third-party cloud endpoint vulnerable to takeover."
            })

        # Fast-Flux / Low TTL
        if dns.get("heuristics", {}).get("fast_flux_suspect"):
            score += 40
            factors.append({
                "weight": 40,
                "title": "Fast-Flux DNS Profile",
                "description": "Rapid TTL rotation across multiple IP addresses to evade IP-level filtering."
            })

        # Bulletproof / High-Risk ASN
        if asn.get("is_bulletproof_suspect"):
            score += 45
            factors.append({
                "weight": 45,
                "title": "High-Risk / Bulletproof Hosting Infrastructure",
                "description": "Hosted in an autonomous system with a history of non-compliance and malicious hosting."
            })

        # Wildcard DNS
        if dns.get("heuristics", {}).get("has_wildcard_dns"):
            score += 15
            factors.append({
                "weight": 15,
                "title": "Wildcard DNS Enabled",
                "description": "Zone responds to all non-existent subdomains, commonly used for dynamic phishing lures."
            })

        return min(100, score), factors

    @classmethod
    def _calculate_exposure(
        cls,
        tls: Dict[str, Any],
        web: Dict[str, Any],
        dns: Dict[str, Any],
        active_scan: Optional[Dict[str, Any]],
        email_sec: Optional[Dict[str, Any]] = None,
        active_probes: Optional[Dict[str, Any]] = None,
        vuln_intel: Optional[Dict[str, Any]] = None,
        web_exposure: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        score = 0
        factors = []

        # Security Headers compliance grade
        sec_headers = web.get("security_headers", {})
        grade = sec_headers.get("grade", "F")
        if grade in ("D", "F"):
            score += 30
            factors.append({
                "weight": 30,
                "title": f"Poor Web Security Headers ({grade} Grade)",
                "description": f"Missing critical browser protections: {', '.join(sec_headers.get('recommendations', [])[:2])}."
            })

        # Expired or self-signed TLS
        live_cert = tls.get("live_cert") or {}
        if live_cert.get("is_expired"):
            score += 40
            factors.append({
                "weight": 40,
                "title": "Expired SSL/TLS Certificate",
                "description": f"Certificate expired on {live_cert.get('not_after')}."
            })
        elif live_cert.get("is_self_signed"):
            score += 35
            factors.append({
                "weight": 35,
                "title": "Self-Signed Certificate",
                "description": "Certificate is not signed by a recognized Certificate Authority."
            })

        # Permissive SPF (+all)
        if dns.get("heuristics", {}).get("suspicious_spf"):
            score += 35
            factors.append({
                "weight": 35,
                "title": "Insecure SPF Policy (+all)",
                "description": "SPF authorizes all internet servers to send mail for this domain."
            })

        # Email Spoofing Exposure (DMARC / BIMI)
        if email_sec and email_sec.get("spoofability", {}).get("status") == "VULNERABLE":
            score += 25
            factors.append({
                "weight": 25,
                "title": "Email Spoofing Exposure (DMARC Unenforced)",
                "description": email_sec["spoofability"].get("summary", "Domain has no enforced DMARC quarantine or reject policy.")
            })

        # Active Probing Findings
        if active_probes:
            exposed_files = active_probes.get("sensitive_files", {}).get("exposed", [])
            if exposed_files:
                score += 50
                factors.append({
                    "weight": 50,
                    "title": f"Exposed Sensitive Files ({len(exposed_files)} artifacts)",
                    "description": f"Accessible sensitive files found: {', '.join([e['title'] for e in exposed_files[:2]])}"
                })
            if active_probes.get("cors_and_methods", {}).get("cors_misconfigured"):
                score += 40
                factors.append({
                    "weight": 40,
                    "title": "CORS Credential Exposure",
                    "description": "Arbitrary cross-origin reflection with credentials enabled."
                })
            if active_probes.get("smtp_relay_starttls", {}).get("open_relay"):
                score += 55
                factors.append({
                    "weight": 55,
                    "title": "SMTP Open Relay Vulnerability",
                    "description": "Mail server accepts unauthorized message forwarding without authentication."
                })

        # Interactive login form on unencrypted or exposed page
        if web.get("dom_analysis", {}).get("has_login_form"):
            score += 20
            factors.append({
                "weight": 20,
                "title": "Interactive Credential Harvesting Form",
                "description": "Page hosts authentication input fields with form submission action."
            })

        # Open management ports (SSH, RDP, FTP) in active scan
        if active_scan and active_scan.get("services"):
            mgmt_ports = [s["port"] for s in active_scan["services"] if s["port"] in (21, 22, 23, 3389)]
            if mgmt_ports:
                score += 30
                factors.append({
                    "weight": 30,
                    "title": f"Exposed Management Services (Ports {', '.join(map(str, mgmt_ports))})",
                    "description": "Publicly exposed remote administration ports detected."
                })

        # Known Vulnerabilities (CISA KEV & EPSS)
        if vuln_intel and vuln_intel.get("cisa_kev_count", 0) > 0:
            score += 45
            factors.append({
                "weight": 45,
                "title": f"Known Exploited Vulnerabilities ({vuln_intel['cisa_kev_count']} CISA KEV)",
                "description": "Detected software versions with active weaponization listed in CISA KEV catalog."
            })

        # Passive Web Exposure (sensitive paths, unauthenticated panels)
        if web_exposure:
            flagged = web_exposure.get("robots_txt", {}).get("sensitive_paths_flagged", [])
            if flagged:
                score += 20
                factors.append({
                    "weight": 20,
                    "title": f"Disclosed Sensitive Administrative Paths ({len(flagged)} paths)",
                    "description": f"Robots.txt discloses internal routes: {', '.join([p.get('path', '') for p in flagged[:3]])}."
                })

        return min(100, score), factors

    @classmethod
    def _calculate_attribution_confidence(cls, tls: Dict[str, Any], dns: Dict[str, Any], whois: Dict[str, Any], web: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
        score = 20  # Base baseline
        factors = []

        # Shared Certificate SANs
        sans = (tls.get("live_cert") or {}).get("sans", [])
        if len(sans) > 1:
            score += 30
            factors.append({
                "weight": 30,
                "title": f"Cryptographic SAN Correlation ({len(sans)} Identities)",
                "description": "Multiple subdomains and hostnames cryptographically bound in the same X.509 certificate."
            })

        # Verified Registrant Org in WHOIS/RDAP
        reg_org = whois.get("registrant_org")
        if reg_org and "privacy" not in reg_org.lower() and "redacted" not in reg_org.lower():
            score += 25
            factors.append({
                "weight": 25,
                "title": f"Direct Registrant Entity ({reg_org})",
                "description": "Domain has published, unmasked corporate entity registration."
            })

        # Favicon MurmurHash3
        fav_hash = web.get("favicon", {}).get("murmur_hash")
        if fav_hash:
            score += 20
            factors.append({
                "weight": 20,
                "title": f"Distinctive Favicon Hash ({fav_hash})",
                "description": "Shodan-compatible MurmurHash3 calculated for pivoting to related web servers."
            })

        # Analytics Tracking Identifiers
        analytics = web.get("dom_analysis", {}).get("analytics_ids", [])
        if analytics:
            score += 25
            factors.append({
                "weight": 25,
                "title": f"Shared Analytics Tracking IDs ({', '.join(analytics[:2])})",
                "description": "Google Analytics / Tag Manager IDs link this site directly to common operator campaigns."
            })

        return min(100, score), factors
