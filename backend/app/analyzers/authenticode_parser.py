"""
Authenticode & Digital Certificate Trust Chain Engine.
Parses PE Authenticode structures (PKCS#7 SignedData containers),
extracts X.509 certificate chains, verifies validity windows, self-signed certificates,
weak signature algorithms, and timestamp counter-signatures.
"""

import struct
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.core.logging_config import logger
from app.analyzers.base import Finding

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def _get_name_attr(name_obj, oid) -> str:
    """Helper to extract an attribute from an x509.Name object safely."""
    try:
        attrs = name_obj.get_attributes_for_oid(oid)
        if attrs:
            val = attrs[0].value
            return str(val) if val is not None else ""
    except Exception:
        pass
    return ""


def parse_authenticode(file_bytes: bytes, cert_offset: int, cert_size: int) -> Dict[str, Any]:
    """
    Parses Windows PE Authenticode digital signature table.
    WIN_CERTIFICATE structure:
      dwLength (4 bytes, uint32)
      wRevision (2 bytes, uint16)
      wCertificateType (2 bytes, uint16)
      bCertificate (variable DER pkcs7 bytes)
    """
    findings: List[Finding] = []
    auth_data: Dict[str, Any] = {
        "is_signed": True,
        "table_offset": hex(cert_offset),
        "table_size": cert_size,
        "certificate_type": "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
        "has_valid_chain": False,
        "trust_status": "UNKNOWN",
        "signer_name": "Unknown",
        "certificates_count": 0,
        "certificates": [],
        "has_timestamp": False,
        "timestamp_type": None,
        "anomalies": []
    }

    if cert_offset + 8 > len(file_bytes):
        auth_data["trust_status"] = "CORRUPTED"
        findings.append(Finding(
            category="structure",
            severity="critical",
            title="Corrupted Authenticode Certificate Table Offset",
            description="Declared Security Directory points beyond physical file boundary."
        ))
        return auth_data, findings

    dw_len, w_rev, w_cert_type = struct.unpack("<IHH", file_bytes[cert_offset : cert_offset + 8])
    auth_data["declared_length"] = dw_len
    auth_data["revision"] = "WIN_CERT_REVISION_2_0 (0x0200)" if w_rev == 0x0200 else hex(w_rev)

    if w_cert_type != 0x0002:
        auth_data["certificate_type"] = f"Non-PKCS#7 Type ({hex(w_cert_type)})"
        auth_data["trust_status"] = "UNSUPPORTED_TYPE"
        return auth_data, findings

    # Extract DER PKCS#7 SignedData payload
    der_len = min(dw_len - 8, len(file_bytes) - (cert_offset + 8))
    if der_len <= 0:
        auth_data["trust_status"] = "EMPTY_PAYLOAD"
        return auth_data, findings

    der_bytes = file_bytes[cert_offset + 8 : cert_offset + 8 + der_len]

    # Timestamp counter-signature detection via OIDs
    # RFC 3161: 1.2.840.113549.1.9.16.1.4
    # MS Authenticode timestamp: 1.3.6.1.4.1.311.3.2.1
    if b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x01\x04" in der_bytes:
        auth_data["has_timestamp"] = True
        auth_data["timestamp_type"] = "RFC 3161 Timestamp Token"
    elif b"\x2b\x06\x01\x04\x01\x82\x37\x03\x02\x01" in der_bytes:
        auth_data["has_timestamp"] = True
        auth_data["timestamp_type"] = "Microsoft Authenticode Timestamp"

    if not CRYPTOGRAPHY_AVAILABLE:
        auth_data["trust_status"] = "PARSER_UNAVAILABLE"
        return auth_data, findings

    try:
        certs = load_der_pkcs7_certificates(der_bytes)
        auth_data["certificates_count"] = len(certs)

        now_utc = datetime.now(timezone.utc)
        parsed_certs: List[Dict[str, Any]] = []
        has_self_signed = False
        has_expired = False
        weak_crypto = False

        for idx, cert in enumerate(certs):
            subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
            subject_org = _get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
            issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
            issuer_org = _get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

            display_name = subject_cn or subject_org or cert.subject.rfc4514_string() or f"Certificate #{idx+1}"
            issuer_display = issuer_cn or issuer_org or cert.issuer.rfc4514_string()

            # Validity
            valid_from = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
            valid_to = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)

            is_expired = (now_utc > valid_to)
            is_not_yet_valid = (now_utc < valid_from)
            is_self_signed = (cert.subject == cert.issuer)

            # Fingerprints
            sha256_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
            sha1_fp = cert.fingerprint(hashes.SHA1()).hex().upper()

            # Format serial
            serial_hex = f"{cert.serial_number:X}"
            if len(serial_hex) % 2 != 0:
                serial_hex = "0" + serial_hex
            serial_formatted = ":".join(serial_hex[i:i+2] for i in range(0, len(serial_hex), 2))

            # Algorithm
            try:
                sig_algo = cert.signature_algorithm_oid._name
            except Exception:
                sig_algo = str(cert.signature_algorithm_oid.dotted_string)

            is_weak = any(w in sig_algo.lower() for w in ["sha1", "md5", "md2"])
            if is_weak:
                weak_crypto = True

            cert_anomalies: List[str] = []
            if is_expired:
                has_expired = True
                cert_anomalies.append(f"Expired on {valid_to.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            if is_not_yet_valid:
                cert_anomalies.append(f"Not yet valid (active after {valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')})")
            if is_self_signed:
                has_self_signed = True
                cert_anomalies.append("Self-signed certificate (Subject equals Issuer)")
            if is_weak:
                cert_anomalies.append(f"Weak signature hashing algorithm ({sig_algo})")

            # Check validity duration
            validity_days = (valid_to - valid_from).days
            if validity_days > 365 * 10:
                cert_anomalies.append(f"Abnormally long validity period ({validity_days // 365} years)")

            # Chain role
            role = "Code Signing (Leaf)" if idx == 0 and len(certs) > 1 else ("Root CA" if is_self_signed else "Intermediate CA")
            if len(certs) == 1 and is_self_signed:
                role = "Self-Signed Code Signer (Untrusted)"

            parsed_certs.append({
                "index": idx,
                "role": role,
                "display_name": display_name,
                "subject": {
                    "common_name": subject_cn,
                    "organization": subject_org,
                    "country": _get_name_attr(cert.subject, NameOID.COUNTRY_NAME),
                    "rfc4514": cert.subject.rfc4514_string()
                },
                "issuer": {
                    "common_name": issuer_cn,
                    "organization": issuer_org,
                    "country": _get_name_attr(cert.issuer, NameOID.COUNTRY_NAME),
                    "rfc4514": cert.issuer.rfc4514_string(),
                    "display": issuer_display
                },
                "serial_number": serial_formatted,
                "valid_from": valid_from.isoformat(),
                "valid_to": valid_to.isoformat(),
                "is_expired": is_expired,
                "is_not_yet_valid": is_not_yet_valid,
                "is_self_signed": is_self_signed,
                "signature_algorithm": sig_algo,
                "sha256_fingerprint": sha256_fp,
                "sha1_fingerprint": sha1_fp,
                "anomalies": cert_anomalies
            })

        auth_data["certificates"] = parsed_certs
        if parsed_certs:
            auth_data["signer_name"] = parsed_certs[0]["display_name"]

        # Evaluate Trust Status
        if has_self_signed and (len(certs) == 1 or parsed_certs[0]["is_self_signed"]):
            auth_data["trust_status"] = "SELF_SIGNED_UNTRUSTED"
            auth_data["anomalies"].append("Binary signed by untrusted self-signed certificate.")
            findings.append(Finding(
                category="structure",
                severity="high",
                title=f"Untrusted Self-Signed Authenticode Certificate ('{auth_data['signer_name']}')",
                description=(
                    f"Executable Authenticode digital signature was generated using a self-signed certificate '{auth_data['signer_name']}'. "
                    "Self-signed signatures lack cryptographic verification from an authoritative trusted Root CA and are commonly created by threat actors."
                ),
                details=auth_data
            ))
        elif has_expired:
            auth_data["trust_status"] = "EXPIRED"
            auth_data["anomalies"].append("One or more certificates in trust chain have expired.")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title=f"Expired Authenticode Digital Signature ('{auth_data['signer_name']}')",
                description=(
                    f"Digital certificate for '{auth_data['signer_name']}' is expired. "
                    "While old software may have expired signatures, adversaries often reuse stolen or lapsed certificates to mimic legitimate vendors."
                ),
                details=auth_data
            ))
        elif weak_crypto:
            auth_data["trust_status"] = "WEAK_ALGORITHM"
            auth_data["anomalies"].append("Certificate chain utilizes deprecated hashing algorithms (SHA-1 / MD5).")
            findings.append(Finding(
                category="structure",
                severity="medium",
                title="Deprecated Authenticode Hash Algorithm (SHA-1 / MD5)",
                description="Certificate chain relies on cryptographically broken hash algorithms susceptible to collision forgery.",
                details=auth_data
            ))
        else:
            auth_data["trust_status"] = "VALID_CHAIN"
            auth_data["has_valid_chain"] = True

    except Exception as e:
        logger.debug(f"Authenticode X.509 parsing failed: {e}")
        auth_data["trust_status"] = "MALFORMED_PKCS7"
        auth_data["parse_error"] = str(e)
        findings.append(Finding(
            category="structure",
            severity="high",
            title="Malformed Authenticode PKCS#7 Structure",
            description=f"Security directory contained unparseable or corrupted PKCS#7 SignedData ASN.1 payload: {e}"
        ))

    return auth_data, findings
