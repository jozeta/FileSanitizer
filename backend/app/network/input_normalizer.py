"""
Universal Input Normalizer & Indicator Classifier.
Handles domains, URLs, IPv4/IPv6, CIDRs, ASNs, email addresses, hashes, and certificate fingerprints.
Performs IDNA/Punycode normalization, homoglyph detection, canonical decomposition,
and anti-SSRF address verification.
"""

import re
import socket
import ipaddress
import urllib.parse
import unicodedata
from typing import Dict, Any, List, Optional, Tuple

from app.network.ssrf import is_ip_blocked, validate_url_for_ssrf
from app.core.logging_config import logger


class InputType:
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    ASN = "asn"
    EMAIL = "email"
    HASH = "hash"
    CERT_FINGERPRINT = "cert_fingerprint"
    UNKNOWN = "unknown"


# Mapping for Homoglyph Confusable Detection
LOOKALIKE_CHAR_MAP = {
    # Cyrillic lowercase
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'п': 'n',
    'т': 't', 'в': 'b', 'г': 'r', 'к': 'k', 'м': 'm', 'н': 'h',
    # Cyrillic uppercase
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
    # Greek
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

# Second-level TLDs to accurately distinguish registrable root domains
SECOND_LEVEL_TLDS = {
    "co", "com", "org", "net", "edu", "gov", "mil", "ac", "asso", "nom", "pp", "tm", "govt", "nic"
}


class NormalizedIndicator:
    def __init__(
        self,
        raw_input: str,
        indicator_type: str,
        normalized_value: str,
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        is_safe_destination: bool = True,
        ssrf_reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.raw_input = raw_input
        self.indicator_type = indicator_type
        self.normalized_value = normalized_value
        self.target_host = target_host
        self.target_port = target_port
        self.is_safe_destination = is_safe_destination
        self.ssrf_reason = ssrf_reason
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_input": self.raw_input,
            "indicator_type": self.indicator_type,
            "normalized_value": self.normalized_value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "is_safe_destination": self.is_safe_destination,
            "ssrf_reason": self.ssrf_reason,
            "details": self.details,
        }


class UniversalInputNormalizer:
    """
    Normalizes, validates, and classifies cyber threat indicators and network assets.
    """

    @classmethod
    def normalize(cls, raw: str) -> NormalizedIndicator:
        """
        Classifies input and returns normalized indicator with safety and metadata annotations.
        """
        clean = (raw or "").strip()
        if not clean:
            return NormalizedIndicator(
                raw_input="",
                indicator_type=InputType.UNKNOWN,
                normalized_value="",
                is_safe_destination=False,
                ssrf_reason="Input is empty"
            )

        # 1. Check for Hashes (MD5, SHA1, SHA256)
        if re.fullmatch(r'[a-fA-F0-9]{32}', clean):
            return NormalizedIndicator(clean, InputType.HASH, clean.lower(), details={"hash_type": "MD5"})
        if re.fullmatch(r'[a-fA-F0-9]{40}', clean):
            return NormalizedIndicator(clean, InputType.HASH, clean.lower(), details={"hash_type": "SHA1"})
        if re.fullmatch(r'[a-fA-F0-9]{64}', clean):
            return NormalizedIndicator(clean, InputType.HASH, clean.lower(), details={"hash_type": "SHA256"})

        # 2. Check for Certificate SHA-256 / SHA-1 fingerprint (with colons or spaces)
        clean_fp = clean.replace(":", "").replace(" ", "").lower()
        if ":" in clean or " " in clean:
            if len(clean_fp) == 64 and re.fullmatch(r'[a-f0-9]{64}', clean_fp):
                return NormalizedIndicator(clean, InputType.CERT_FINGERPRINT, clean_fp, details={"algo": "SHA-256"})
            if len(clean_fp) == 40 and re.fullmatch(r'[a-f0-9]{40}', clean_fp):
                return NormalizedIndicator(clean, InputType.CERT_FINGERPRINT, clean_fp, details={"algo": "SHA-1"})

        # 3. Check for Autonomous System Number (ASN)
        asn_match = re.fullmatch(r'(?:AS|as)?(\d{1,10})', clean)
        if asn_match and ("as" in clean.lower() or int(asn_match.group(1)) > 65535 or clean.upper().startswith("AS")):
            asn_num = int(asn_match.group(1))
            return NormalizedIndicator(clean, InputType.ASN, f"AS{asn_num}", details={"asn_number": asn_num})

        # 4. Check for CIDR block
        if "/" in clean:
            try:
                net = ipaddress.ip_network(clean, strict=False)
                is_safe = not is_ip_blocked(net.network_address)
                return NormalizedIndicator(
                    clean,
                    InputType.CIDR,
                    str(net),
                    is_safe_destination=is_safe,
                    ssrf_reason=None if is_safe else f"CIDR {net} belongs to private/reserved space",
                    details={"version": net.version, "prefixlen": net.prefixlen, "num_addresses": net.num_addresses}
                )
            except ValueError:
                pass

        # 5. Check for Email Address
        if "@" in clean and not ("://" in clean):
            email_match = re.fullmatch(r'^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$', clean)
            if email_match:
                domain_part = email_match.group(1).lower().rstrip(".")
                return NormalizedIndicator(
                    clean,
                    InputType.EMAIL,
                    clean.lower(),
                    target_host=domain_part,
                    details={"local_part": clean.split("@")[0], "domain": domain_part}
                )

        # 6. Check for Raw IPv4 or IPv6
        is_ip, ip_obj = cls._parse_ip(clean)
        if is_ip and ip_obj:
            ip_str = str(ip_obj)
            is_blocked = is_ip_blocked(ip_obj)
            return NormalizedIndicator(
                clean,
                InputType.IPV4 if ip_obj.version == 4 else InputType.IPV6,
                ip_str,
                target_host=ip_str,
                is_safe_destination=not is_blocked,
                ssrf_reason=None if not is_blocked else f"IP {ip_str} is in private/internal range (SSRF blocked)",
                details={"version": ip_obj.version, "is_private": ip_obj.is_private, "is_loopback": ip_obj.is_loopback}
            )

        # 7. Check for Full URL vs. Domain
        has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', clean))
        url_to_parse = clean if has_scheme else f"http://{clean}"
        
        try:
            parsed = urllib.parse.urlparse(url_to_parse)
        except Exception as e:
            return NormalizedIndicator(clean, InputType.UNKNOWN, clean, is_safe_destination=False, ssrf_reason=f"Failed to parse URL/domain: {e}")

        hostname = (parsed.hostname or "").strip().rstrip(".").lower()
        if not hostname:
            return NormalizedIndicator(clean, InputType.UNKNOWN, clean, is_safe_destination=False, ssrf_reason="Invalid host format")

        # Punycode & IDNA normalization
        idna_domain, puny_details = cls._normalize_idna(hostname)

        # Registrable root domain extraction
        root_domain = cls.extract_registrable_domain(idna_domain)

        # Check if URL or Domain
        is_full_url = has_scheme or (parsed.path and parsed.path != "/") or bool(parsed.query) or bool(parsed.fragment)

        # Port extraction: only assign default 80/443 if an explicit scheme or URL was supplied, otherwise None
        target_port = parsed.port
        if not target_port:
            if has_scheme:
                target_port = 443 if parsed.scheme.lower() == "https" else 80
            else:
                target_port = None

        # SSRF check on target host/URL
        ssrf_port = target_port or (443 if (has_scheme and parsed.scheme.lower() == "https") else 80)
        is_safe, ssrf_reason, resolved_ips = validate_url_for_ssrf(f"http://{idna_domain}:{ssrf_port}")

        details: Dict[str, Any] = {
            "canonical_hostname": idna_domain,
            "root_domain": root_domain,
            "port": target_port,
            "scheme": parsed.scheme.lower() if has_scheme else None,
            "path": parsed.path or "/",
            "query": parsed.query,
            "fragment": parsed.fragment,
            "resolved_ips": resolved_ips or [],
            "homoglyph_analysis": puny_details,
            "has_credentials": bool(parsed.username or parsed.password)
        }

        # Dword / Octal / Hex IP obfuscation checks on host
        obf = cls._detect_obfuscation(hostname)
        if obf["is_obfuscated"]:
            details["obfuscation"] = obf

        if is_full_url and has_scheme:
            # Reconstruct clean canonical URL without credentials or fragments
            clean_url = f"{parsed.scheme.lower()}://{idna_domain}"
            if (parsed.scheme.lower() == "http" and target_port != 80) or (parsed.scheme.lower() == "https" and target_port != 443):
                clean_url += f":{target_port}"
            clean_url += parsed.path or "/"
            if parsed.query:
                clean_url += f"?{parsed.query}"

            return NormalizedIndicator(
                clean,
                InputType.URL,
                clean_url,
                target_host=idna_domain,
                target_port=target_port,
                is_safe_destination=is_safe,
                ssrf_reason=ssrf_reason,
                details=details
            )

        # Otherwise treat as Domain / FQDN
        return NormalizedIndicator(
            clean,
            InputType.DOMAIN,
            idna_domain,
            target_host=idna_domain,
            target_port=target_port,
            is_safe_destination=is_safe,
            ssrf_reason=ssrf_reason,
            details=details
        )

    @classmethod
    def _parse_ip(cls, s: str) -> Tuple[bool, Optional[ipaddress.IPv4Address or ipaddress.IPv6Address]]:
        """Parses an IPv4 or IPv6 string, including bracketed IPv6."""
        target = s.strip()
        if target.startswith("[") and "]" in target:
            target = target[1:target.index("]")]
        try:
            ip = ipaddress.ip_address(target)
            return True, ip
        except ValueError:
            return False, None

    @classmethod
    def _normalize_idna(cls, hostname: str) -> Tuple[str, Dict[str, Any]]:
        """Encodes/decodes IDNA Punycode and checks for homoglyph lookalikes."""
        unicode_rendered = hostname
        is_punycode = "xn--" in hostname.lower()

        try:
            if is_punycode:
                unicode_rendered = hostname.encode("ascii").decode("idna")
            else:
                hostname = hostname.encode("idna").decode("ascii")
        except Exception:
            pass

        spoofed_chars = []
        is_homograph = False
        for ch in unicode_rendered:
            if ord(ch) > 127:
                lookalike = LOOKALIKE_CHAR_MAP.get(ch)
                if lookalike:
                    is_homograph = True
                spoofed_chars.append({
                    "char": ch,
                    "codepoint": f"U+{ord(ch):04X}",
                    "name": unicodedata.name(ch, "UNKNOWN"),
                    "latin_lookalike": lookalike or ""
                })

        simulated_latin = "".join(LOOKALIKE_CHAR_MAP.get(ch, ch) for ch in unicode_rendered)

        return hostname.lower(), {
            "is_punycode": is_punycode or "xn--" in hostname.lower(),
            "punycode": hostname.lower(),
            "unicode_rendered": unicode_rendered,
            "is_homograph": is_homograph,
            "is_confusable": is_homograph,
            "simulated_latin": simulated_latin,
            "spoofed_chars": spoofed_chars,
        }

    @classmethod
    def extract_registrable_domain(cls, domain: str) -> str:
        """Extracts the registered apex domain using known two-level TLD heuristics."""
        clean = domain.strip().lower().rstrip(".")
        if not clean or cls._parse_ip(clean)[0]:
            return clean

        parts = clean.split(".")
        if len(parts) <= 2:
            return clean

        if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_TLDS and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    @classmethod
    def _detect_obfuscation(cls, host: str) -> Dict[str, Any]:
        """Detects DWORD, hex, and octal IP obfuscation."""
        techniques = []
        if host.isdigit():
            try:
                num = int(host)
                if 0 < num < 4294967295:
                    ip = socket.inet_ntoa(num.to_bytes(4, byteorder='big'))
                    techniques.append({"type": "DWORD_IP", "description": f"Dword integer {num} resolves to IPv4 {ip}"})
            except Exception:
                pass
        if "0x" in host.lower():
            techniques.append({"type": "HEX_IP", "description": "Hexadecimal notation in host string"})
        if re.search(r'\b0\d{2,3}\.', host):
            techniques.append({"type": "OCTAL_IP", "description": "Octal notation in IP octets"})

        return {
            "is_obfuscated": len(techniques) > 0,
            "techniques": techniques
        }
