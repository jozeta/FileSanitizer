"""
Email Security, Spoofability & Brand Integrity Audit.
Inspects DMARC policy, common DKIM selector records, and BIMI brand indicators.
Evaluates email spoofability posture and CEO fraud / BEC exposure.
"""

import re
from typing import Dict, Any, List, Optional
import dns.resolver
from app.core.logging_config import logger


COMMON_DKIM_SELECTORS = [
    "google", "default", "k1", "s1", "selector1", "mail", "dkim", "2023", "2024", "pic", "email", "smtp"
]


class EmailSecurityAuditor:
    """
    Audits DMARC, DKIM, and BIMI DNS records to determine domain email spoofability.
    """

    @classmethod
    def audit(cls, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower().rstrip(".")
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.5

        result: Dict[str, Any] = {
            "domain": clean_domain,
            "dmarc": {
                "present": False,
                "raw_record": None,
                "policy": "none",
                "subdomain_policy": None,
                "percentage": 100,
                "aggregate_reports": [],
                "forensic_reports": [],
                "adkim": "r",  # relaxed default
                "aspf": "r",   # relaxed default
                "is_enforced": False
            },
            "dkim": {
                "selectors_checked": len(COMMON_DKIM_SELECTORS),
                "selectors_found": [],
            },
            "bimi": {
                "present": False,
                "raw_record": None,
                "svg_logo_url": None,
                "vmc_cert_url": None,
                "has_vmc": False
            },
            "spoofability": {
                "status": "VULNERABLE",  # VULNERABLE, PARTIALLY_PROTECTED, SECURED
                "risk_score": 85,        # 0 to 100 (100 = trivially spoofable)
                "summary": "Domain has no DMARC policy or is set to p=none. Attackers can forge emails from this domain.",
                "remediations": []
            }
        }

        # 1. DMARC Check (_dmarc.<domain>)
        dmarc_name = f"_dmarc.{clean_domain}"
        try:
            answers = resolver.resolve(dmarc_name, "TXT")
            for r in answers:
                txt = r.to_text().strip('"').strip()
                if txt.startswith("v=DMARC1"):
                    result["dmarc"]["present"] = True
                    result["dmarc"]["raw_record"] = txt
                    cls._parse_dmarc(txt, result["dmarc"])
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DMARC lookup note for {clean_domain}: {e}")

        # 2. DKIM Selector Probing
        for sel in COMMON_DKIM_SELECTORS:
            dkim_name = f"{sel}._domainkey.{clean_domain}"
            try:
                answers = resolver.resolve(dkim_name, "TXT")
                for r in answers:
                    txt = r.to_text().strip('"').strip()
                    if "v=DKIM1" in txt or "p=" in txt:
                        key_size = cls._estimate_key_size(txt)
                        result["dkim"]["selectors_found"].append({
                            "selector": sel,
                            "record": txt[:120] + ("..." if len(txt) > 120 else ""),
                            "key_size_bits": key_size
                        })
                        break
            except Exception:
                continue

        # 3. BIMI Check (default._bimi.<domain>)
        bimi_name = f"default._bimi.{clean_domain}"
        try:
            answers = resolver.resolve(bimi_name, "TXT")
            for r in answers:
                txt = r.to_text().strip('"').strip()
                if txt.startswith("v=BIMI1"):
                    result["bimi"]["present"] = True
                    result["bimi"]["raw_record"] = txt
                    cls._parse_bimi(txt, result["bimi"])
                    break
        except Exception:
            pass

        # 4. Compute Spoofability Rating
        cls._evaluate_spoofability(result)
        return result

    @classmethod
    def _parse_dmarc(cls, txt: str, dmarc: Dict[str, Any]) -> None:
        tags = [t.strip() for t in txt.split(";") if t.strip()]
        for tag in tags:
            if "=" not in tag:
                continue
            k, v = tag.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "p":
                dmarc["policy"] = v.lower()
                dmarc["is_enforced"] = v.lower() in ("quarantine", "reject")
            elif k == "sp":
                dmarc["subdomain_policy"] = v.lower()
            elif k == "pct":
                try:
                    dmarc["percentage"] = int(v)
                except ValueError:
                    pass
            elif k == "rua":
                dmarc["aggregate_reports"] = [m.replace("mailto:", "").strip() for m in v.split(",")]
            elif k == "ruf":
                dmarc["forensic_reports"] = [m.replace("mailto:", "").strip() for m in v.split(",")]
            elif k == "adkim":
                dmarc["adkim"] = v.lower()
            elif k == "aspf":
                dmarc["aspf"] = v.lower()

    @classmethod
    def _parse_bimi(cls, txt: str, bimi: Dict[str, Any]) -> None:
        tags = [t.strip() for t in txt.split(";") if t.strip()]
        for tag in tags:
            if "=" not in tag:
                continue
            k, v = tag.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "l":
                bimi["svg_logo_url"] = v
            elif k == "a":
                bimi["vmc_cert_url"] = v
                bimi["has_vmc"] = bool(v and v.lower() != "none")

    @classmethod
    def _estimate_key_size(cls, txt: str) -> Optional[int]:
        m = re.search(r'p=([a-zA-Z0-9+/=]+)', txt)
        if m:
            b64_len = len(m.group(1))
            approx_bytes = (b64_len * 3) // 4
            if approx_bytes > 240:
                return 2048
            elif approx_bytes > 120:
                return 1024
        return None

    @classmethod
    def _evaluate_spoofability(cls, res: Dict[str, Any]) -> None:
        dmarc = res["dmarc"]
        sp = res["spoofability"]
        recs = []

        if not dmarc["present"]:
            sp["status"] = "VULNERABLE"
            sp["risk_score"] = 90
            sp["summary"] = "No DMARC policy published. Domain is unprotected and can be easily spoofed in spear-phishing campaigns."
            recs.append("Publish a DMARC policy at _dmarc." + res["domain"])
            recs.append("Start with 'p=none' for telemetry monitoring, then transition to 'p=quarantine' or 'p=reject'")
        elif dmarc["policy"] == "none":
            sp["status"] = "VULNERABLE"
            sp["risk_score"] = 70
            sp["summary"] = "DMARC policy is set to 'p=none' (Monitoring only). Receiving mail servers will accept spoofed emails without quarantine or rejection."
            recs.append("Upgrade DMARC policy to 'p=quarantine' or 'p=reject' to actively block unauthorized senders")
        elif dmarc["policy"] == "quarantine":
            sp["status"] = "PARTIALLY_PROTECTED"
            sp["risk_score"] = 35
            pct = dmarc.get("percentage", 100)
            sp["summary"] = f"DMARC is set to quarantine ({pct}% of messages). Unauthenticated emails are sent to junk/spam folders."
            if pct < 100:
                recs.append(f"Increase DMARC pct= from {pct}% to 100%")
            recs.append("Graduate to 'p=reject' for strict spoofing prevention")
        elif dmarc["policy"] == "reject":
            sp["status"] = "SECURED"
            sp["risk_score"] = 5
            sp["summary"] = "Strict DMARC enforcement active (p=reject). Unauthorized emails pretending to come from this domain are automatically rejected by compliant mail servers."

        if not res["dkim"]["selectors_found"]:
            recs.append("Ensure DKIM cryptographic signatures are enabled across all outbound mail services")

        if not res["bimi"]["present"]:
            recs.append("Consider implementing BIMI (Brand Indicators for Message Identification) to display verified logos in client inboxes")

        sp["remediations"] = recs
