"""
Automated Forensic Deobfuscator & String Decoding Engine.
Supports Security Decoder operations for Malware Research, CTF, Incident Response, and Vulnerability Analysis:
- Single-byte XOR brute-force scanner with plaintext anchor matching
- Recursive Base64 decoder (supporting UTF-16LE PowerShell -EncodedCommand and ASCII)
- Hex stream decoder
- ROT13 & URL decoding
- Automatic hidden IOC (URLs, IPs, domains, commands) extraction from deobfuscated streams
"""

import base64
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from app.core.logging_config import logger

# Common plaintext anchors used to identify valid single-byte XOR keys
XOR_PLAINTEXT_ANCHORS = [
    b"http://", b"https://", b"powershell", b"cmd.exe", b"This program",
    b"/bin/sh", b"/bin/bash", b"eval(", b"system(", b"CreateObject",
    b"WScript", b"Net.WebClient", b"DownloadString", b"Invoke-Expression",
    b"VirtualAlloc", b"WriteProcessMemory", b"kernel32", b"ntdll",
    b"<?php", b"base64_decode", b"SELECT ", b"FROM "
]

# Regex patterns for secondary IOC extraction
RE_URL = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+', re.IGNORECASE)
RE_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
RE_DOMAIN = re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|xyz|ru|cn|info|top|cc|biz|edu|gov|se|de|uk)\b', re.IGNORECASE)


def _extract_urls(text: str) -> List[str]:
    raw_urls = RE_URL.findall(text)
    clean_urls = []
    for u in raw_urls:
        cleaned = re.sub(r'[\'\"\)\],;>]+$', '', u)
        if cleaned and cleaned not in clean_urls:
            clean_urls.append(cleaned)
    return clean_urls


class Deobfuscator:
    """Forensic string decoding and payload deobfuscation engine."""

    @staticmethod
    def rot13(text: str) -> str:
        """Apply ROT13 substitution cipher."""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def rot47(text: str) -> str:
        """Apply ROT47 ASCII rotation cipher (printable ASCII 33 to 126)."""
        result = []
        for char in text:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code + 14) % 94)))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def caesar_bruteforce(text: str) -> List[Dict[str, Any]]:
        """
        Brute-force all 25 Caesar cipher shifts and rank by English letter frequency.
        """
        english_freq = {'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95, 's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32}
        results = []
        for shift in range(1, 26):
            shifted = []
            for c in text:
                if 'a' <= c <= 'z':
                    shifted.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
                elif 'A' <= c <= 'Z':
                    shifted.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
                else:
                    shifted.append(c)
            cand = "".join(shifted)
            cand_lower = cand.lower()
            score = sum(cand_lower.count(k) * weight for k, weight in english_freq.items())
            results.append({"shift": shift, "text": cand, "score": round(score, 1)})

        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    @staticmethod
    def html_entity_decode(text: str) -> str:
        """Decode decimal, hex, and named HTML entities (e.g. &#x68;&#116;&#116;&#112;)."""
        import html
        return html.unescape(text)

    @staticmethod
    def url_double_decode(text: str) -> str:
        """Perform recursive URL decoding until stable."""
        curr = text
        for _ in range(3):
            nxt = urllib.parse.unquote(curr)
            if nxt == curr:
                break
            curr = nxt
        return curr

    @staticmethod
    def base85_decode(text: str) -> Optional[str]:
        """Decode Ascii85 and RFC 1924 Base85 encoded data."""
        cleaned = text.strip()
        try:
            raw = base64.a85decode(cleaned.encode("ascii"))
            return raw.decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            raw = base64.b85decode(cleaned.encode("ascii"))
            return raw.decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    @staticmethod
    def reverse_string(text: str) -> str:
        """Reverse string order."""
        return text[::-1]

    @staticmethod
    def defang_ioc(text: str) -> str:
        """Defang URLs, IPs, and domains for safe sharing."""
        res = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp').replace('://', '[://]'), text)
        res = re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1[.]\2[.]\3[.]\4', res)
        return res

    @staticmethod
    def refang_ioc(text: str) -> str:
        """Refang defanged IOCs back into actionable addresses."""
        res = text.replace('hxxps://', 'https://').replace('hxxp://', 'http://')
        res = res.replace('hxxps[://]', 'https://').replace('hxxp[://]', 'http://')
        res = res.replace('[://]', '://').replace('(:)', ':')
        res = res.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
        return res

    @staticmethod
    def convert_ip_formats(ip_or_dword: str) -> Dict[str, str]:
        """
        Converts between Dword, Hex, Octal, and standard dot-decimal IPv4 formats.
        """
        import ipaddress
        s = ip_or_dword.strip()
        try:
            if s.isdigit():
                val = int(s)
                ip_obj = ipaddress.IPv4Address(val)
            elif s.startswith("0x") or s.startswith("0X"):
                val = int(s, 16)
                ip_obj = ipaddress.IPv4Address(val)
            else:
                ip_obj = ipaddress.IPv4Address(s)

            ip_int = int(ip_obj)
            octets = [int(o) for o in str(ip_obj).split(".")]
            return {
                "dot_decimal": str(ip_obj),
                "dword": str(ip_int),
                "hex": hex(ip_int),
                "octal": f"0{oct(octets[0])[2:]}.0{oct(octets[1])[2:]}.0{oct(octets[2])[2:]}.0{oct(octets[3])[2:]}"
            }
        except Exception:
            return {}

    @staticmethod
    def url_decode(text: str) -> str:
        """Decode URL percentage-encoded string."""
        return urllib.parse.unquote(text)

    @staticmethod
    def hex_decode(text: str) -> Optional[str]:
        """Decode continuous or delimiter-separated hex stream."""
        cleaned = re.sub(r'[^a-fA-F0-9]', '', text)
        if len(cleaned) < 4 or len(cleaned) % 2 != 0:
            return None
        try:
            raw = bytes.fromhex(cleaned)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def decode_base64_block(b64_str: str) -> Optional[Dict[str, Any]]:
        """
        Decodes a base64 string, checking for UTF-16LE (PowerShell -EncodedCommand),
        standard ASCII/UTF-8, and binary headers (PE / ELF / ZIP).
        """
        clean_str = re.sub(r'\s+', '', b64_str)
        # Pad if necessary
        missing_padding = len(clean_str) % 4
        if missing_padding:
            clean_str += '=' * (4 - missing_padding)

        try:
            decoded_bytes = base64.b64decode(clean_str, validate=False)
            if len(decoded_bytes) < 4:
                return None

            # 1. Check for embedded binary executable or archive signatures
            if decoded_bytes.startswith(b"MZ"):
                return {
                    "encoded": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                    "encoded_full": b64_str,
                    "decoded": f"[Decoded Windows PE Executable/DLL Header (MZ) - {len(decoded_bytes)} bytes]",
                    "encoding": "Binary PE/MZ Executable",
                    "bytes_len": len(decoded_bytes),
                    "is_binary": True
                }
            if decoded_bytes.startswith(b"\x7fELF"):
                return {
                    "encoded": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                    "encoded_full": b64_str,
                    "decoded": f"[Decoded Linux ELF Executable Header - {len(decoded_bytes)} bytes]",
                    "encoding": "Binary ELF Executable",
                    "bytes_len": len(decoded_bytes),
                    "is_binary": True
                }
            if decoded_bytes.startswith(b"PK\x03\x04"):
                return {
                    "encoded": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                    "encoded_full": b64_str,
                    "decoded": f"[Decoded ZIP Archive Payload - {len(decoded_bytes)} bytes]",
                    "encoding": "ZIP Archive",
                    "bytes_len": len(decoded_bytes),
                    "is_binary": True
                }

            # 2. Check if UTF-16LE encoded (ASCII text in UTF-16LE has null bytes in every second position)
            text_utf16 = None
            if len(decoded_bytes) >= 4 and len(decoded_bytes) % 2 == 0:
                null_ratio = decoded_bytes[1::2].count(0) / (len(decoded_bytes) // 2)
                if null_ratio > 0.35:
                    try:
                        candidate = decoded_bytes.decode("utf-16le")
                        printable_chars = sum(1 for c in candidate if c.isprintable() or c in '\r\n\t')
                        if len(candidate) > 0 and (printable_chars / len(candidate)) > 0.75:
                            text_utf16 = candidate
                    except Exception:
                        pass

            text_utf8 = None
            try:
                candidate = decoded_bytes.decode("utf-8", errors="strict")
                printable_chars = sum(1 for c in candidate if c.isprintable() or c in '\r\n\t')
                if len(candidate) > 0 and (printable_chars / len(candidate)) > 0.75:
                    text_utf8 = candidate
            except Exception:
                # Fallback with ignore/replace if largely ASCII
                candidate = decoded_bytes.decode("ascii", errors="ignore")
                if len(candidate) > 4 and (len(candidate) / len(decoded_bytes)) > 0.65:
                    text_utf8 = candidate

            result_text = text_utf16 or text_utf8
            if not result_text or len(result_text.strip()) < 2:
                return None

            encoding = "UTF-16LE (PowerShell)" if text_utf16 else "UTF-8 / ASCII"
            return {
                "encoded": b64_str[:80] + ("..." if len(b64_str) > 80 else ""),
                "encoded_full": b64_str,
                "decoded": result_text,
                "encoding": encoding,
                "bytes_len": len(decoded_bytes),
                "is_binary": False
            }
        except Exception:
            return None

    @classmethod
    def scan_for_base64_blocks(cls, text: str) -> List[Dict[str, Any]]:
        """Finds and decodes base64 strings embedded in scripts, commands, or documents."""
        candidates = set()

        # 1. PowerShell command-line argument: -enc / -e / -encodedcommand
        for m in re.finditer(r'(?i)(?:-enc|-encodedcommand|-e|-ec)\s+["\']?([A-Za-z0-9+/=]{12,})["\']?', text):
            candidates.add(m.group(1).strip())

        # 2. PowerShell FromBase64String("...")
        for m in re.finditer(r'(?i)frombase64string\s*\(\s*["\']([A-Za-z0-9+/=]{12,})["\']\s*\)', text):
            candidates.add(m.group(1).strip())

        # 3. Quoted base64 strings
        for m in re.finditer(r'["\']([A-Za-z0-9+/=]{16,})["\']', text):
            candidates.add(m.group(1).strip())

        # 4. Standalone continuous base64 word boundaries (min length 16)
        for m in re.finditer(r'\b[A-Za-z0-9+/]{16,}={0,2}\b', text):
            candidates.add(m.group(0).strip())

        results = []
        seen_decoded = set()

        for cand in candidates:
            # Skip if only hex or numbers
            if re.fullmatch(r'[0-9]+', cand) or (len(cand) > 30 and re.fullmatch(r'[0-9a-fA-F]+', cand)):
                continue

            res = cls.decode_base64_block(cand)
            if res and res["decoded"] not in seen_decoded:
                seen_decoded.add(res["decoded"])
                # Extract any IOCs discovered inside the decoded text
                urls = _extract_urls(res["decoded"])
                ips = [ip for ip in RE_IPV4.findall(res["decoded"]) if not ip.startswith("127.") and not ip.startswith("0.")]
                res["extracted_urls"] = urls
                res["extracted_ips"] = ips
                results.append(res)

        # Sort longer decoded strings first
        results.sort(key=lambda x: len(x.get("decoded", "")), reverse=True)
        return results

    @classmethod
    def xor_brute_force(cls, raw_data: bytes, min_hit_score: int = 1) -> List[Dict[str, Any]]:
        """
        Brute-force single-byte XOR (keys 0x01 to 0xFF) across raw binary data.
        Returns keys that reveal known plaintext malware/exploit anchors.
        """
        results = []
        if not raw_data or len(raw_data) < 8:
            return results

        data_sample = raw_data[:50000]  # Cap sample to 50KB for speed

        for key in range(1, 256):
            # Fast bytearray XOR
            decrypted = bytes([b ^ key for b in data_sample])
            matched_anchors = []

            for anchor in XOR_PLAINTEXT_ANCHORS:
                if anchor.lower() in decrypted.lower():
                    matched_anchors.append(anchor.decode("ascii", errors="ignore"))

            if len(matched_anchors) >= min_hit_score:
                # Extract printable strings from this decrypted stream
                printable_strings = []
                cur = []
                for b in decrypted:
                    if 32 <= b <= 126 or b in (9, 10, 13):
                        cur.append(chr(b))
                    else:
                        if len(cur) >= 6:
                            printable_strings.append("".join(cur))
                        cur = []
                if len(cur) >= 6:
                    printable_strings.append("".join(cur))

                sample_text = "\n".join(printable_strings[:10])
                urls = _extract_urls(sample_text)
                ips = [ip for ip in RE_IPV4.findall(sample_text) if not ip.startswith("127.")]

                results.append({
                    "key_hex": f"0x{key:02X}",
                    "key_decimal": key,
                    "matched_anchors": matched_anchors,
                    "revealed_strings_sample": sample_text[:400],
                    "extracted_urls": urls,
                    "extracted_ips": ips
                })

        return results

    @classmethod
    def analyze_payload(cls, content: str or bytes) -> Dict[str, Any]:
        """
        Comprehensive automated deobfuscation analysis of text or raw file bytes.
        """
        if isinstance(content, str):
            raw_bytes = content.encode("utf-8", errors="replace")
            text_corpus = content
        else:
            raw_bytes = content
            text_corpus = content.decode("utf-8", errors="replace")

        # 1. Base64 block discovery
        b64_results = cls.scan_for_base64_blocks(text_corpus)

        # 2. XOR brute-force
        xor_results = cls.xor_brute_force(raw_bytes)

        # 3. Hex decoding if long continuous hex exists
        hex_results = []
        hex_blocks = re.findall(r'\b(?:[0-9a-fA-F]{2}){16,}\b', text_corpus)
        for hb in hex_blocks[:5]:
            decoded = cls.hex_decode(hb)
            if decoded and any(anchor.decode("ascii", errors="ignore") in decoded for anchor in XOR_PLAINTEXT_ANCHORS[:6]):
                hex_results.append({
                    "raw_hex": hb[:60] + "...",
                    "decoded": decoded[:200]
                })

        all_extracted_urls = set()
        all_extracted_ips = set()

        for b in b64_results:
            all_extracted_urls.update(b.get("extracted_urls", []))
            all_extracted_ips.update(b.get("extracted_ips", []))

        for x in xor_results:
            all_extracted_urls.update(x.get("extracted_urls", []))
            all_extracted_ips.update(x.get("extracted_ips", []))

        has_findings = bool(b64_results or xor_results or hex_results)

        return {
            "has_deobfuscated_content": has_findings,
            "base64_blocks": b64_results,
            "xor_candidates": xor_results,
            "hex_candidates": hex_results,
            "extracted_urls": list(all_extracted_urls),
            "extracted_ips": list(all_extracted_ips),
            "summary": (
                f"Deobfuscation revealed {len(b64_results)} decoded Base64 blocks, "
                f"{len(xor_results)} XOR candidate keys, and "
                f"{len(all_extracted_urls) + len(all_extracted_ips)} secondary IOCs."
                if has_findings else "No obfuscated or encrypted payloads identified."
            )
        }
