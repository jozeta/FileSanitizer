"""
Passive Certificate Transparency (CT) & TLS Inspector.
Performs passive TLS handshake to extract cipher suite, protocol version, certificate chain,
issuer authority, SANs, and SHA-256 fingerprint.
Queries public Certificate Transparency logs (crt.sh) for historical certificates and SAN subdomain discovery.
"""

import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
import httpx

from app.core.logging_config import logger


class TLSInspector:
    """
    Executes passive TLS handshakes and Certificate Transparency log audits.
    """

    @classmethod
    def inspect(cls, target_host: str, port: int = 443, query_ct_logs: bool = True) -> Dict[str, Any]:
        """
        Inspects TLS configuration and queries crt.sh CT logs.
        """
        clean_host = target_host.strip().lower().rstrip(".")
        effective_port = 443 if (not port or port == 80) else port

        result: Dict[str, Any] = {
            "target": clean_host,
            "port": effective_port,
            "has_tls": False,
            "live_cert": None,
            "ct_logs": {
                "queried": False,
                "total_certificates_found": 0,
                "discovered_subdomains": [],
                "issuers": [],
                "recent_entries": []
            },
            "security_findings": []
        }

        # 1. Passive Live TLS Handshake
        cert_info = cls._perform_tls_handshake(clean_host, effective_port)
        if not cert_info and effective_port != 443:
            # Fallback to standard 443 if custom port didn't answer with TLS
            cert_info = cls._perform_tls_handshake(clean_host, 443)
            if cert_info:
                effective_port = 443
                result["port"] = 443

        if cert_info:
            result["has_tls"] = True
            result["live_cert"] = cert_info

            # Add security findings from cert evaluation
            if cert_info.get("is_expired"):
                result["security_findings"].append({
                    "severity": "high",
                    "title": "Expired SSL/TLS Certificate",
                    "description": f"Certificate expired on {cert_info.get('not_after')}."
                })
            elif cert_info.get("days_remaining") is not None and cert_info.get("days_remaining") < 14:
                result["security_findings"].append({
                    "severity": "medium",
                    "title": f"Expiring Soon ({cert_info.get('days_remaining')} Days Remaining)",
                    "description": f"Certificate will expire on {cert_info.get('not_after')}."
                })

            if cert_info.get("is_self_signed"):
                result["security_findings"].append({
                    "severity": "high",
                    "title": "Self-Signed Certificate Detected",
                    "description": "The certificate is self-signed and not trusted by recognized public Certificate Authorities."
                })

            tls_ver = cert_info.get("tls_version", "")
            if tls_ver in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                result["security_findings"].append({
                    "severity": "high",
                    "title": f"Deprecated TLS Protocol ({tls_ver})",
                    "description": "Legacy TLS versions contain known cryptographic vulnerabilities (POODLE, BEAST) and lack modern cipher protection."
                })

        # 2. Certificate Transparency Logs via crt.sh
        if query_ct_logs and not cls._is_ip(clean_host):
            ct_info = cls._query_crt_sh(clean_host)
            result["ct_logs"] = ct_info

        # Also populate discovered subdomains from live cert SANs
        if result.get("live_cert") and result["live_cert"].get("sans"):
            if "discovered_subdomains" not in result.get("ct_logs", {}):
                result["ct_logs"]["discovered_subdomains"] = list(result["ct_logs"].get("logged_subdomains", []))
            existing = set(result["ct_logs"]["discovered_subdomains"])
            for san in result["live_cert"]["sans"]:
                san_clean = san.strip().lstrip("*.").rstrip(".").lower()
                if san_clean and (san_clean == clean_host or san_clean.endswith(f".{clean_host}")) and not cls._is_ip(san_clean):
                    existing.add(san_clean)
            result["ct_logs"]["discovered_subdomains"] = sorted(list(existing))

        return result

    @classmethod
    def _is_ip(cls, s: str) -> bool:
        """Check if string is IPv4 or IPv6."""
        try:
            socket.inet_aton(s)
            return True
        except Exception:
            try:
                socket.inet_pton(socket.AF_INET6, s)
                return True
            except Exception:
                return False

    @classmethod
    def _perform_tls_handshake(cls, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Connects via TLS and extracts certificate metadata and cipher details."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We inspect regardless of validity

        server_name = None if cls._is_ip(host) else host

        try:
            with socket.create_connection((host, port), timeout=5.0) as sock:
                try:
                    ssock = ctx.wrap_socket(sock, server_hostname=server_name)
                except ssl.SSLError:
                    # Retry without SNI server_hostname if server rejected it
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = socket.create_connection((host, port), timeout=5.0)
                    ssock = ctx.wrap_socket(sock, server_hostname=None)

                with ssock:
                    tls_version = ssock.version()
                    cipher_info = ssock.cipher()  # (name, protocol, bits)
                    der_cert = ssock.getpeercert(binary_form=True)

                    if not der_cert:
                        return None

                    sha256_fp = hashlib.sha256(der_cert).hexdigest()
                    sha1_fp = hashlib.sha1(der_cert).hexdigest()

                    sans: List[str] = []
                    subject_info: Dict[str, Optional[str]] = {"common_name": None, "organization": None, "country": None}
                    issuer_info: Dict[str, Optional[str]] = {"common_name": None, "organization": None, "country": None}
                    not_before_str: Optional[str] = None
                    not_after_str: Optional[str] = None
                    days_remaining: Optional[int] = None
                    is_expired = False
                    is_self_signed = False
                    serial_number: Optional[str] = None

                    try:
                        from cryptography import x509
                        from cryptography.x509.oid import NameOID, ExtensionOID
                        
                        cert = x509.load_der_x509_certificate(der_cert)
                        serial_number = hex(cert.serial_number)

                        # Subject
                        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                        if cns:
                            subject_info["common_name"] = str(cns[0].value)
                        orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                        if orgs:
                            subject_info["organization"] = str(orgs[0].value)
                        countries = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
                        if countries:
                            subject_info["country"] = str(countries[0].value)

                        # Issuer
                        icns = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                        if icns:
                            issuer_info["common_name"] = str(icns[0].value)
                        iorgs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                        if iorgs:
                            issuer_info["organization"] = str(iorgs[0].value)
                        icountries = cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
                        if icountries:
                            issuer_info["country"] = str(icountries[0].value)

                        # SANs
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            for name in san_ext.value:
                                sans.append(str(name.value).lower())
                        except Exception:
                            pass

                        # Dates
                        try:
                            nb = cert.not_valid_before_utc
                        except AttributeError:
                            nb = cert.not_valid_before
                        try:
                            na = cert.not_valid_after_utc
                        except AttributeError:
                            na = cert.not_valid_after

                        if nb:
                            not_before_str = nb.isoformat()
                        if na:
                            if na.tzinfo is None:
                                na = na.replace(tzinfo=timezone.utc)
                            not_after_str = na.isoformat()
                            delta = na - datetime.now(timezone.utc)
                            days_remaining = delta.days
                            is_expired = days_remaining < 0

                        # Self-signed check
                        is_self_signed = (cert.issuer == cert.subject)

                    except Exception as parse_err:
                        logger.debug(f"x509 cert parse note: {parse_err}")

                    return {
                        "tls_version": tls_version,
                        "cipher_suite": cipher_info[0] if cipher_info else None,
                        "cipher_bits": cipher_info[2] if cipher_info else None,
                        "subject": subject_info,
                        "issuer": issuer_info,
                        "sans": sans,
                        "sha256_fingerprint": sha256_fp,
                        "sha1_fingerprint": sha1_fp,
                        "serial_number": serial_number,
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "days_remaining": days_remaining,
                        "is_expired": is_expired,
                        "is_self_signed": is_self_signed
                    }

        except Exception as e:
            logger.debug(f"TLS handshake failed for {host}:{port}: {e}")
            return None

    @classmethod
    def _query_crt_sh(cls, domain: str) -> Dict[str, Any]:
        """
        Queries crt.sh JSON endpoint for public Certificate Transparency records.
        Extracts discovered subdomains and historical certificate issuances.
        """
        ct_result: Dict[str, Any] = {
            "queried": True,
            "total_certificates_found": 0,
            "discovered_subdomains": [],
            "issuers": [],
            "recent_entries": []
        }

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            with httpx.Client(timeout=7.0, headers={"User-Agent": "FileSanitizer-SecurityScanner/1.0"}) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    entries = resp.json()
                    ct_result["total_certificates_found"] = len(entries)

                    subdomains_set: Set[str] = set()
                    issuers_set: Set[str] = set()
                    recent: List[Dict[str, Any]] = []

                    for entry in entries[:60]:  # Limit to 60 most recent entries
                        cn = (entry.get("common_name") or "").strip().lower()
                        name_val = (entry.get("name_value") or "").strip().lower()
                        issuer = (entry.get("issuer_name") or "").strip()
                        logged_at = entry.get("entry_timestamp")

                        # Collect subdomains
                        for sub_candidate in [cn] + name_val.split("\n"):
                            sub_clean = sub_candidate.strip().lstrip("*.").rstrip(".")
                            if sub_clean and domain in sub_clean and not cls._is_ip(sub_clean):
                                subdomains_set.add(sub_clean)

                        if issuer:
                            # Shorten issuer name for readability
                            for part in issuer.split(","):
                                if part.strip().startswith("O=") or part.strip().startswith("CN="):
                                    issuers_set.add(part.split("=")[1].strip('"'))

                        if len(recent) < 10:
                            recent.append({
                                "id": entry.get("id"),
                                "common_name": cn,
                                "logged_at": logged_at,
                                "not_before": entry.get("not_before"),
                                "not_after": entry.get("not_after"),
                            })

                    ct_result["discovered_subdomains"] = sorted(list(subdomains_set))
                    ct_result["issuers"] = sorted(list(issuers_set))
                    ct_result["recent_entries"] = recent

        except Exception as e:
            logger.debug(f"crt.sh query exception for {domain}: {e}")

        return ct_result
