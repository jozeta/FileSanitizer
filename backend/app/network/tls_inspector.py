"""
Passive Certificate Transparency (CT) & TLS Inspector.
Performs passive TLS handshake to extract cipher suite, protocol version, certificate chain,
issuer authority, SANs, and SHA-256 fingerprint.
Queries public Certificate Transparency logs (crt.sh) for historical certificates and SAN subdomain discovery.
"""

import ssl
import socket
import hashlib
import concurrent.futures
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
import ipaddress
import httpx

from app.core.logging_config import logger


# Cryptographic evaluations and security flaw rationales for TLS cipher suites
CIPHER_SECURITY_CATALOG: Dict[str, Dict[str, Any]] = {
    # Modern Recommended AEAD Ciphers
    "TLS_AES_256_GCM_SHA384": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.3",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-256-GCM",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "Modern authenticated encryption (AEAD) with Perfect Forward Secrecy. Top-tier cryptographic security (NIST SP 800-52r2)."
    },
    "TLS_CHACHA20_POLY1305_SHA256": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.3",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "ChaCha20-Poly1305",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "High-performance authenticated AEAD stream cipher with constant-time execution resistant to CPU cache timing side-channels."
    },
    "TLS_AES_128_GCM_SHA256": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.3",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-128-GCM",
        "mac": "AEAD",
        "bits": 128,
        "explanation": "Standard AEAD cipher with Perfect Forward Secrecy, recommended by NIST, IETF RFC 8446, and OWASP TLS guidelines."
    },
    "ECDHE-ECDSA-AES256-GCM-SHA384": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-256-GCM",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "Elliptic curve Ephemeral Diffie-Hellman with ECDSA signature and AES-256-GCM authenticated encryption."
    },
    "ECDHE-RSA-AES256-GCM-SHA384": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-256-GCM",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "Elliptic curve Ephemeral Diffie-Hellman with RSA signature and AES-256-GCM authenticated encryption."
    },
    "ECDHE-RSA-AES128-GCM-SHA256": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-128-GCM",
        "mac": "AEAD",
        "bits": 128,
        "explanation": "Standard TLS 1.2 AEAD cipher with Perfect Forward Secrecy. Excellent balance of security and hardware-accelerated throughput."
    },
    "ECDHE-RSA-CHACHA20-POLY1305": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "ChaCha20-Poly1305",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "ChaCha20-Poly1305 AEAD with Perfect Forward Secrecy for modern mobile and browser TLS 1.2 clients."
    },
    "DHE-RSA-AES256-GCM-SHA384": {
        "status": "RECOMMENDED",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "DHE (PFS)",
        "encryption": "AES-256-GCM",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "Diffie-Hellman key exchange with AEAD encryption. (Requires DH parameter size ≥ 2048-bit to prevent Logjam)."
    },
    # Acceptable Ciphers (Legacy CBC mode, but with PFS)
    "ECDHE-RSA-AES256-SHA384": {
        "status": "ACCEPTABLE",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-256-CBC",
        "mac": "SHA384",
        "bits": 256,
        "explanation": "Supports Perfect Forward Secrecy with strong SHA-384 HMAC, but uses legacy CBC block mode rather than modern AEAD."
    },
    "ECDHE-RSA-AES128-SHA256": {
        "status": "ACCEPTABLE",
        "is_weak": False,
        "protocol": "TLSv1.2",
        "key_exchange": "ECDHE (PFS)",
        "encryption": "AES-128-CBC",
        "mac": "SHA256",
        "bits": 128,
        "explanation": "Supports Perfect Forward Secrecy, but uses CBC mode. Modern deployments prefer AES-GCM or ChaCha20-Poly1305."
    },
    # Weak / Flawed Ciphers (Flagged with detailed flaw explanations)
    "AES256-GCM-SHA384": {
        "status": "WEAK",
        "is_weak": True,
        "protocol": "TLSv1.2",
        "key_exchange": "RSA (Static)",
        "encryption": "AES-256-GCM",
        "mac": "AEAD",
        "bits": 256,
        "explanation": "Lacks Perfect Forward Secrecy (PFS). Uses static RSA key exchange where future private key disclosure allows retroactive decryption of past traffic captures."
    },
    "AES128-GCM-SHA256": {
        "status": "WEAK",
        "is_weak": True,
        "protocol": "TLSv1.2",
        "key_exchange": "RSA (Static)",
        "encryption": "AES-128-GCM",
        "mac": "AEAD",
        "bits": 128,
        "explanation": "Lacks Perfect Forward Secrecy (PFS). If the server private key is leaked or compromised in the future, all previously recorded sessions can be decrypted."
    },
    "AES256-SHA": {
        "status": "WEAK",
        "is_weak": True,
        "protocol": "TLSv1.0/1.2",
        "key_exchange": "RSA (Static)",
        "encryption": "AES-256-CBC",
        "mac": "SHA1",
        "bits": 256,
        "explanation": "Triple vulnerability: Lacks Forward Secrecy (static RSA), uses CBC padding vulnerable to Lucky Thirteen timing attacks, and relies on deprecated SHA-1."
    },
    "AES128-SHA": {
        "status": "WEAK",
        "is_weak": True,
        "protocol": "TLSv1.0/1.2",
        "key_exchange": "RSA (Static)",
        "encryption": "AES-128-CBC",
        "mac": "SHA1",
        "bits": 128,
        "explanation": "Lacks Forward Secrecy, uses legacy CBC mode vulnerable to timing attacks, and uses deprecated SHA-1 HMAC."
    },
    "DES-CBC3-SHA": {
        "status": "INSECURE",
        "is_weak": True,
        "protocol": "TLSv1.0/1.2",
        "key_exchange": "RSA (Static)",
        "encryption": "3DES-EDE-CBC",
        "mac": "SHA1",
        "bits": 112,
        "explanation": "Sweet32 Vulnerability (CVE-2016-2183): 64-bit block size allows collision attacks in long TLS sessions, allowing attackers to recover sensitive authentication cookies. Deprecated by NIST SP 800-131A."
    },
    "RC4-SHA": {
        "status": "BROKEN",
        "is_weak": True,
        "protocol": "TLSv1.0",
        "key_exchange": "RSA (Static)",
        "encryption": "RC4-128",
        "mac": "SHA1",
        "bits": 128,
        "explanation": "Bar Mitzvah / RC4 NOMORE Attacks: Severe statistical biases in the RC4 keystream allow practical plaintext recovery and session cookie extraction. Strictly prohibited by RFC 7465."
    },
    "RC4-MD5": {
        "status": "BROKEN",
        "is_weak": True,
        "protocol": "TLSv1.0",
        "key_exchange": "RSA (Static)",
        "encryption": "RC4-128",
        "mac": "MD5",
        "bits": 128,
        "explanation": "Completely broken: RC4 stream cipher biases plus broken MD5 collision resistance. Vulnerable to POODLE, Bar Mitzvah, and SLOTH collision attacks."
    }
}


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

            # 1b. Supported Cipher Suites Audit
            ciphers_audit = cls._audit_supported_ciphers(
                clean_host, effective_port, cert_info.get("cipher_suite"), cert_info.get("tls_version")
            )
            result["cipher_suites_audit"] = ciphers_audit

            if isinstance(ciphers_audit, dict) and ciphers_audit.get("has_weak_ciphers"):
                weak_list = ciphers_audit.get("weak_ciphers", [])
                weak_names = [c["name"] for c in weak_list[:3]]
                result["security_findings"].append({
                    "severity": "high" if any(c.get("status") in ("INSECURE", "BROKEN") for c in weak_list) else "medium",
                    "title": f"Weak / Insecure Cipher Suites Supported ({len(weak_list)})",
                    "description": f"Server supports weak or flawed cipher suites ({', '.join(weak_names)}). Susceptible to cryptographic downgrade, lack of forward secrecy, or plaintext recovery."
                })
        else:
            result["cipher_suites_audit"] = {
                "active_cipher": None,
                "active_protocol": None,
                "total_cataloged": 0,
                "supported_count": 0,
                "weak_ciphers_count": 0,
                "has_weak_ciphers": False,
                "weak_ciphers": [],
                "ciphers": []
            }

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
    def _is_safe_host(cls, host: str, port: int = 443) -> Tuple[bool, Optional[str]]:
        """Validate destination against SSRF: resolve IPs and ensure none are private/loopback/cloud metadata."""
        from app.network.ssrf import is_ip_blocked
        try:
            if cls._is_ip(host):
                ip_obj = ipaddress.ip_address(host)
                if is_ip_blocked(ip_obj):
                    return False, None
                return True, host

            addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            if not addr_info:
                return False, None
            safe_ip = None
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(ip_str)
                if is_ip_blocked(ip_obj):
                    return False, None
                if not safe_ip:
                    safe_ip = ip_str
            return True, safe_ip
        except Exception:
            return False, None

    @classmethod
    def _perform_tls_handshake(cls, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Connects via TLS and extracts certificate metadata and cipher details."""
        is_safe, target_ip = cls._is_safe_host(host, port)
        if not is_safe or not target_ip:
            logger.warning(f"[TLSInspector] SSRF guard blocked TLS connection attempt to {host}:{port}")
            return None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We inspect regardless of validity

        server_name = None if cls._is_ip(host) else host

        try:
            with socket.create_connection((target_ip, port), timeout=5.0) as sock:
                try:
                    ssock = ctx.wrap_socket(sock, server_hostname=server_name)
                except ssl.SSLError:
                    # Retry without SNI server_hostname if server rejected it
                    try:
                        sock.close()
                    except Exception:
                        pass
                    sock = socket.create_connection((target_ip, port), timeout=5.0)
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

    @classmethod
    def _audit_supported_ciphers(
        cls, host: str, port: int, active_cipher: Optional[str], active_proto: Optional[str]
    ) -> Dict[str, Any]:
        """
        Audits and tests supported cipher suites for the host.
        Identifies weak or broken ciphers and provides technical explanations.
        """
        ciphers_list: List[Dict[str, Any]] = []
        supported_weak: List[Dict[str, Any]] = []
        seen_ciphers: Set[str] = set()

        candidates_to_test = [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "DES-CBC3-SHA",
            "RC4-SHA",
            "RC4-MD5"
        ]

        is_safe, target_ip = cls._is_safe_host(host, port)
        probe_results: Dict[str, bool] = {}

        if is_safe and target_ip:
            def _test_single_cipher(c_name: str) -> Tuple[str, bool]:
                if active_cipher and c_name.lower() == active_cipher.lower():
                    return c_name, True
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    try:
                        ctx.set_ciphers(c_name)
                    except ssl.SSLError:
                        return c_name, False

                    server_name = None if cls._is_ip(host) else host
                    with socket.create_connection((target_ip, port), timeout=0.8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                            return c_name, True
                except Exception:
                    return c_name, False

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                fut_to_cipher = {executor.submit(_test_single_cipher, c): c for c in candidates_to_test}
                for fut in concurrent.futures.as_completed(fut_to_cipher, timeout=2.5):
                    try:
                        c_name, is_sup = fut.result()
                        probe_results[c_name] = is_sup
                    except Exception:
                        pass

        for c_name, meta in CIPHER_SECURITY_CATALOG.items():
            is_active = bool(active_cipher and c_name.lower() == active_cipher.lower())
            is_supported = probe_results.get(c_name, False) or is_active

            entry = {
                "name": c_name,
                "protocol": meta["protocol"],
                "key_exchange": meta["key_exchange"],
                "encryption": meta["encryption"],
                "mac": meta["mac"],
                "bits": meta["bits"],
                "status": meta["status"],
                "is_weak": meta["is_weak"],
                "supported": is_supported,
                "active_negotiated": is_active,
                "explanation": meta["explanation"]
            }
            ciphers_list.append(entry)
            seen_ciphers.add(c_name.lower())
            if is_supported and meta["is_weak"]:
                supported_weak.append(entry)

        if active_cipher and active_cipher.lower() not in seen_ciphers:
            ciphers_list.insert(0, {
                "name": active_cipher,
                "protocol": active_proto or "TLS",
                "key_exchange": "ECDHE (PFS)" if "ECDHE" in active_cipher else ("DHE" if "DHE" in active_cipher else "RSA"),
                "encryption": "AES" if "AES" in active_cipher else "Symmetric",
                "mac": "AEAD" if "GCM" in active_cipher or "POLY1305" in active_cipher else "HMAC",
                "bits": 256 if "256" in active_cipher else 128,
                "status": "RECOMMENDED" if ("GCM" in active_cipher or "POLY1305" in active_cipher) else "ACCEPTABLE",
                "is_weak": False,
                "supported": True,
                "active_negotiated": True,
                "explanation": "Active negotiated cipher suite in live TLS handshake."
            })

        ciphers_list.sort(key=lambda x: (
            not x["active_negotiated"],
            not x["supported"],
            not x["is_weak"],
            x["name"]
        ))

        supported_count = sum(1 for c in ciphers_list if c["supported"])

        return {
            "active_cipher": active_cipher,
            "active_protocol": active_proto,
            "total_cataloged": len(ciphers_list),
            "supported_count": supported_count,
            "weak_ciphers_count": len(supported_weak),
            "has_weak_ciphers": len(supported_weak) > 0,
            "weak_ciphers": supported_weak,
            "ciphers": ciphers_list
        }
