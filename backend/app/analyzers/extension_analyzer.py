"""
Chrome & Edge Browser Extension Forensic Security & Privacy Analyzer.
Analyzes .crx packages (CRX2/CRX3) and unpacked/zipped extensions.
Evaluates Manifest V2/V3 structure, permission risk scoring, CSP security,
background worker persistence, content script injection scopes,
and performs static heuristic code scanning on bundled JavaScript files.
"""

import io
import re
import json
import zipfile
import hashlib
import base64
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import httpx

from app.core.logging_config import logger

# Permission risk classifications
CRITICAL_PERMISSIONS = {
    "<all_urls>": "Full read and write access to all visited websites and DOM data",
    "*://*/*": "Full read and write access to all HTTP and HTTPS websites",
    "http://*/*": "Access to all insecure HTTP traffic and webpages",
    "https://*/*": "Access to all secure HTTPS traffic and webpages",
    "debugger": "Can attach DevTools protocol debugger to inspect and modify browser internals",
    "webrequest": "Can intercept and inspect all network requests and headers",
    "webrequestblocking": "Can block, alter, or redirect active network requests in flight",
    "cookies": "Can read, write, and export authentication and session cookies",
    "nativemessaging": "Can execute and communicate with arbitrary native binaries on the host OS",
    "management": "Can install, uninstall, enable, or disable other browser extensions",
    "proxy": "Can route browser web traffic through arbitrary external proxy servers",
    "declarativenetrequestfeedback": "Can read sensitive request headers and block actions"
}

HIGH_PERMISSIONS = {
    "tabs": "Access to browser tab URLs, titles, and lifecycle events",
    "activetab": "Temporary access to current active webpage DOM and content",
    "scripting": "Can inject arbitrary JavaScript code into web pages",
    "clipboardread": "Can read sensitive clipboard data, passwords, or tokens",
    "clipboardwrite": "Can modify clipboard contents",
    "history": "Can read, search, and delete full user browsing history",
    "bookmarks": "Can read and modify user bookmarks",
    "webnavigation": "Notified of real-time URL navigation and transitions",
    "geolocation": "Can access real-time physical geographic location",
    "identity": "Can obtain OAuth tokens and user identity information",
    "declarativenetrequest": "Can inspect and modify network requests declaratively",
    "storage": "Can store and read local persistent data",
    "unlimitedstorage": "Unrestricted local disk storage without quota limits"
}

MEDIUM_PERMISSIONS = {
    "downloads": "Can trigger and manage background file downloads",
    "notifications": "Can display system desktop notifications",
    "alarms": "Can schedule recurring background timer events",
    "contextmenus": "Can inject custom menu items into right-click menus",
    "idle": "Can detect user idle / away state",
    "power": "Can prevent system display sleep",
    "sessions": "Can query and restore recently closed browser sessions"
}

# Suspicious JavaScript heuristics
JS_SUSPICIOUS_PATTERNS = [
    (re.compile(r'\beval\s*\(', re.I), "Dynamic code execution via eval()", "HIGH", "T1059.007"),
    (re.compile(r'new\s+Function\s*\(', re.I), "Dynamic function constructor execution", "HIGH", "T1059.007"),
    (re.compile(r'chrome\.cookies\.(?:get|getAll)\s*\(', re.I), "Authentication cookie harvesting via chrome.cookies API", "CRITICAL", "T1539"),
    (re.compile(r'document\.cookie\b', re.I), "Access to DOM session cookies", "MEDIUM", "T1539"),
    (re.compile(r'localStorage\.(?:getItem|setItem)\s*\(', re.I), "Direct local storage inspection or modification", "LOW", "T1005"),
    (re.compile(r'(?:addEventListener|attachEvent)\s*\(\s*["\']key(?:down|press|up)["\']', re.I), "Keystroke event listener (Potential Keylogger)", "CRITICAL", "T1056.001"),
    (re.compile(r'input\[type=["\']password["\']\]', re.I), "DOM query targeting password input fields", "CRITICAL", "T1056.001"),
    (re.compile(r'chrome\.tabs\.executeScript\s*\(|chrome\.scripting\.executeScript\s*\(', re.I), "Dynamic code injection into web pages", "HIGH", "T1055"),
    (re.compile(r'navigator\.sendBeacon\s*\(', re.I), "Background asynchronous telemetry/exfiltration beacon", "MEDIUM", "T1041"),
    (re.compile(r'new\s+WebSocket\s*\(', re.I), "Persistent bidirectional WebSocket communication", "MEDIUM", "T1071.001"),
    (re.compile(r'chrome\.webRequest\.(?:onBeforeRequest|onBeforeSendHeaders)\.addListener', re.I), "Network traffic interception hook", "HIGH", "T1040"),
    (re.compile(r'String\.fromCharCode\s*\(', re.I), "Character code string obfuscation", "MEDIUM", "T1027"),
    (re.compile(r'unescape\s*\(\s*["\']%[0-9a-fA-F]', re.I), "Percent-encoded payload decoding", "MEDIUM", "T1027"),
]


class ExtensionAnalyzer:
    """
    Forensic security and privacy analyzer for Chrome and Edge browser extensions.
    """

    @classmethod
    def is_extension_package(cls, file_path: Path, filename: str = "") -> bool:
        """Determine if file is a .crx or contains a Chrome extension manifest.json."""
        name_lower = filename.lower()
        if name_lower.endswith(".crx"):
            return True

        # Check CRX magic Cr24
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"Cr24"):
                    return True
                # If ZIP archive, check if manifest.json exists
                if header.startswith(b"PK\x03\x04"):
                    f.seek(0)
                    with zipfile.ZipFile(f, "r") as zf:
                        names = [n.lower() for n in zf.namelist()]
                        if "manifest.json" in names or any(n.endswith("/manifest.json") for n in names):
                            return True
        except Exception:
            pass

        return False

    @classmethod
    def analyze(cls, file_path: Path, filename: str) -> Dict[str, Any]:
        """Analyze CRX or ZIP extension package."""
        result: Dict[str, Any] = {
            "is_extension": True,
            "filename": filename,
            "crx_version": None,
            "manifest_version": None,
            "extension_id": None,
            "name": "Unknown Extension",
            "version": "0.0.0",
            "description": "",
            "author": "",
            "homepage_url": "",
            "update_url": "",
            "risk_score": 0,
            "risk_level": "CLEAN",
            "permissions": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "host_permissions": []
            },
            "background": {
                "has_background": False,
                "is_persistent": False,
                "service_worker": None,
                "scripts": []
            },
            "content_scripts": [],
            "csp": {
                "raw": "",
                "allows_unsafe_eval": False,
                "allows_unsafe_inline": False,
                "allows_remote_scripts": False
            },
            "author": "",
            "developer_url": "",
            "homepage_url": "",
            "update_url": "",
            "is_webstore_signed": False,
            "package_signatures_count": 0,
            "verified_item_id": None,
            "verified_item_version": None,
            "copyright_notice": None,
            "web_accessible_resources": [],
            "js_findings": [],
            "store_intelligence": None,
            "risk_flags": [],
            "summary": ""
        }

        # 1. Extract ZIP data from CRX or plain ZIP
        zip_bytes, crx_ver = cls._extract_zip_bytes(file_path)
        result["crx_version"] = crx_ver

        if not zip_bytes:
            result["risk_flags"].append({
                "severity": "high",
                "title": "Corrupt or Unreadable Extension Archive",
                "description": "Failed to parse CRX package or embedded ZIP filesystem."
            })
            result["risk_level"] = "HIGH RISK"
            return result

        # 2. Open ZIP and parse manifest.json & package signatures
        manifest_data = None
        ext_id = None
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                manifest_data = cls._read_manifest(zf)
                if not manifest_data:
                    result["risk_flags"].append({
                        "severity": "high",
                        "title": "Missing manifest.json",
                        "description": "Extension archive does not contain a valid manifest.json definition file."
                    })
                    result["risk_level"] = "HIGH RISK"
                    return result

                # Parse manifest metadata
                cls._parse_manifest_metadata(manifest_data, result)

                # Check for official Web Store verified contents signatures
                if "_metadata/verified_contents.json" in zf.namelist():
                    try:
                        vc_raw = zf.read("_metadata/verified_contents.json").decode("utf-8", errors="ignore")
                        vc_data = json.loads(vc_raw)
                        for vc_entry in vc_data:
                            payload_b64 = vc_entry.get("signed_content", {}).get("payload", "")
                            if payload_b64:
                                payload_bytes = base64.b64decode(payload_b64 + "==")
                                payload_obj = json.loads(payload_bytes.decode("utf-8", errors="ignore"))
                                if payload_obj.get("item_id"):
                                    result["verified_item_id"] = payload_obj["item_id"]
                                    if not ext_id:
                                        ext_id = payload_obj["item_id"]
                                if payload_obj.get("item_version"):
                                    result["verified_item_version"] = payload_obj["item_version"]
                                result["is_webstore_signed"] = True
                                result["package_signatures_count"] = len(vc_entry.get("signed_content", {}).get("signatures", []))
                    except Exception as vc_err:
                        logger.debug(f"Verified contents parsing note: {vc_err}")

                # Check package.json and LICENSE for author & publisher info
                for fname in zf.namelist():
                    fname_lower = fname.lower()
                    if fname_lower == "package.json" or fname_lower.endswith("/package.json"):
                        try:
                            pkg_data = json.loads(zf.read(fname).decode("utf-8", errors="ignore"))
                            if not result.get("author") and pkg_data.get("author"):
                                result["author"] = str(pkg_data["author"])
                            if pkg_data.get("homepage"):
                                result["homepage_url"] = result.get("homepage_url") or pkg_data["homepage"]
                        except Exception:
                            pass
                    elif "license" in fname_lower:
                        try:
                            lic_text = zf.read(fname).decode("utf-8", errors="ignore")
                            c_match = re.search(r'Copyright\s+(?:\(c\)\s*)?(?:[0-9]{4}[,\-\s]*)*(.*?)(?:\.|\r|\n|$)', lic_text, re.I)
                            if c_match and not result.get("copyright_notice"):
                                result["copyright_notice"] = c_match.group(1).strip()
                        except Exception:
                            pass

                # Scan JavaScript source files inside package
                cls._scan_extension_scripts(zf, result)

        except zipfile.BadZipFile:
            result["risk_flags"].append({
                "severity": "high",
                "title": "Malformed Extension Archive",
                "description": "The ZIP container is corrupted or truncated."
            })
            result["risk_level"] = "HIGH RISK"
            return result
        except Exception as e:
            logger.error(f"Extension analysis error for {filename}: {e}")

        # 3. Detect Extension ID and Query External Store Intelligence
        if not ext_id:
            m_id = re.search(r'\b([a-p]{32})\b', filename.lower())
            if m_id:
                ext_id = m_id.group(1)
            elif manifest_data and manifest_data.get("key"):
                try:
                    pub_bytes = base64.b64decode(manifest_data["key"])
                    digest = hashlib.sha256(pub_bytes).hexdigest()[:32]
                    ext_id = ''.join(chr(ord('a') + int(c, 16)) for c in digest)
                except Exception:
                    pass

        if not ext_id:
            # Check CRX2 header pubkey
            try:
                with open(file_path, "rb") as f:
                    header = f.read(16)
                    if header.startswith(b"Cr24"):
                        import struct
                        ver, pub_len = struct.unpack("<II", header[4:12])
                        if ver == 2 and 0 < pub_len < 4096:
                            pub_bytes = f.read(pub_len)
                            digest = hashlib.sha256(pub_bytes).hexdigest()[:32]
                            ext_id = ''.join(chr(ord('a') + int(c, 16)) for c in digest)
            except Exception:
                pass

        if ext_id:
            result["extension_id"] = ext_id
            try:
                store_intel = cls.query_webstore_intelligence(ext_id, fallback_author=result.get("author"))
                result["store_intelligence"] = store_intel
            except Exception as store_err:
                logger.debug(f"Web store intelligence lookup error for {ext_id}: {store_err}")

        # 4. Calculate Overall Risk Score
        cls._calculate_risk_score(result)

        return result

    @classmethod
    def query_webstore_intelligence(cls, ext_id: str, fallback_author: Optional[str] = None) -> Dict[str, Any]:
        """
        Query Chrome Web Store and Microsoft Edge Add-ons for
        community metrics, users count, downloads, review ratings, developer/owner,
        ESB allowlist status, and overall community reputation verdict.
        """
        import datetime

        cookies = {
            'SOCS': 'CAESHAgBEhJnd3NfMjAyNDA5MjQtMF9SQzIaAmVuIAEaBgiA_L2yBg',
            'CONSENT': 'YES+cb.20230531-04-p0.en+FX+999'
        }
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        intel: Dict[str, Any] = {
            "extension_id": ext_id,
            "store_name": "Chrome Web Store",
            "users_count": None,
            "downloads_count": None,
            "rating": None,
            "reviews_count": None,
            "developer_owner": fallback_author or None,
            "last_update_date": None,
            "store_version": None,
            "featured_badge": False,
            "google_esb_allowlist": False,
            "store_url": f"https://chromewebstore.google.com/detail/{ext_id}",
            "reputation_score": 50,
            "reputation_verdict": "UNVERIFIED",
            "reputation_summary": ""
        }

        # 1. Query Google updatecheck API for ESB allowlist status
        try:
            up_url = f"https://clients2.google.com/service/update2/crx?response=updatecheck&prodversion=120.0&x=id%3D{ext_id}%26uc"
            with httpx.Client(timeout=4.0) as client:
                up_r = client.get(up_url, headers=headers)
                if up_r.status_code == 200:
                    if '_esbAllowlist="true"' in up_r.text:
                        intel["google_esb_allowlist"] = True
                    if 'status="ok"' in up_r.text:
                        intel["is_active_in_store"] = True
        except Exception as e:
            logger.debug(f"Google updatecheck note: {e}")

        # 2. Scrape Chrome Web Store metadata & data callbacks
        found_cws = False
        try:
            cws_url = f"https://chromewebstore.google.com/detail/{ext_id}?hl=en"
            with httpx.Client(timeout=6.0, cookies=cookies, headers=headers, follow_redirects=True) as client:
                r = client.get(cws_url)
                if r.status_code == 200:
                    html = r.text

                    # Parse Google AF_initDataCallback payloads (structured data array)
                    cbs = re.findall(r'data:(\[\[.*?\]\]),\s*sideChannel:', html, re.DOTALL)
                    for cb in cbs:
                        try:
                            data = json.loads(cb)
                            for entry in data:
                                if isinstance(entry, list) and len(entry) > 14:
                                    if entry[0] == ext_id or not intel["users_count"]:
                                        found_cws = True
                                        if isinstance(entry[3], (int, float)):
                                            intel["rating"] = round(float(entry[3]), 2)
                                        if entry[4]:
                                            intel["reviews_count"] = f"{entry[4]:,} reviews" if isinstance(entry[4], int) else str(entry[4])
                                        if entry[14]:
                                            cnt = entry[14]
                                            intel["downloads_count"] = cnt if isinstance(cnt, int) else None
                                            intel["users_count"] = f"{cnt:,}+ users" if isinstance(cnt, int) else str(cnt)
                                        if len(entry) > 17 and isinstance(entry[17], list) and entry[17]:
                                            try:
                                                intel["last_update_date"] = datetime.datetime.utcfromtimestamp(entry[17][0]).strftime('%B %d, %Y')
                                            except Exception:
                                                pass
                                        if entry[0] == ext_id:
                                            break
                        except Exception:
                            pass

                    # Fallback regexes
                    if not intel["users_count"]:
                        m_users = re.search(r'([0-9,KM\.]+\+?\s+users)', html, re.I)
                        if m_users:
                            intel["users_count"] = m_users.group(1).strip()
                            found_cws = True

                    if not intel["rating"]:
                        m_rating = re.search(r'Average rating\s+([0-9\.]+)\s+out of 5 stars', html, re.I) or re.search(r'aria-label=[\"\']([0-9\.]+)\s+stars', html, re.I)
                        if m_rating:
                            try:
                                intel["rating"] = float(m_rating.group(1))
                                found_cws = True
                            except Exception:
                                pass

                    if not intel["reviews_count"]:
                        m_reviews = re.search(r'([0-9,K\.]+)\s+ratings', html, re.I)
                        if m_reviews:
                            intel["reviews_count"] = m_reviews.group(1).strip()

                    # Developer / Publisher
                    m_dev = re.search(r'<a[^>]+rel=[\"\']ugc nofollow[\"\'][^>]*>([^<]+)</a>', html) or re.search(r'Developer\s*</div>\s*<div>([^<]+)</div>', html)
                    if m_dev:
                        cand_dev = m_dev.group(1).strip()
                        if cand_dev.lower() not in ['privacy policy', 'developer dashboard', 'terms of service', 'support']:
                            intel["developer_owner"] = cand_dev

                    # Updated date
                    if not intel["last_update_date"]:
                        m_updated = re.search(r'>Updated</div>\s*<div>([^<]+)</div>', html)
                        if m_updated:
                            intel["last_update_date"] = m_updated.group(1).strip()

                    # Store Version
                    m_ver = re.search(r'>Version</div>\s*<div[^>]*>([^<]+)</div>', html)
                    if m_ver:
                        intel["store_version"] = m_ver.group(1).strip()

                    # Featured / Verified publisher badge
                    if "The publisher has a good record" in html or "Featured" in html or "Established publisher" in html:
                        intel["featured_badge"] = True
        except Exception as e:
            logger.debug(f"Chrome Web Store scrape note: {e}")

        # 3. Fallback to Microsoft Edge Add-ons if unlisted on CWS
        if not found_cws:
            try:
                edge_url = f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}"
                with httpx.Client(timeout=4.0, headers=headers, follow_redirects=True) as client:
                    edge_r = client.get(edge_url)
                    if edge_r.status_code == 200 and "Microsoft Edge Add-ons" in edge_r.text:
                        intel["store_name"] = "Microsoft Edge Add-ons"
                        intel["store_url"] = edge_url
                        found_cws = True
            except Exception:
                pass

        # 4. Community Reputation Synthesis
        score = 50
        if intel["google_esb_allowlist"]:
            score += 25
        if intel["featured_badge"]:
            score += 15

        downloads = intel.get("downloads_count")
        if downloads:
            if downloads >= 1_000_000:
                score += 25
            elif downloads >= 100_000:
                score += 15
            elif downloads >= 10_000:
                score += 10
            elif downloads >= 1_000:
                score += 5
        elif intel.get("users_count") and any(k in intel["users_count"].lower() for k in ["m", "million", "000"]):
            score += 15

        if intel.get("rating"):
            if intel["rating"] >= 4.5:
                score += 10
            elif intel["rating"] >= 3.8:
                score += 5
            elif intel["rating"] < 2.5:
                score -= 20

        if not found_cws and not intel.get("users_count") and not intel["google_esb_allowlist"]:
            score = 25
            verdict = "UNLISTED_OR_SIDELOADED"
            summary = "Extension was not located in official Chrome Web Store or Edge Add-ons. Sideloaded package or internal developer deployment."
        elif score >= 80:
            verdict = "VERIFIED_AND_POPULAR"
            user_txt = intel.get('users_count') or f"{downloads:,}+ users" if downloads else "High community adoption"
            summary = f"High reputation extension verified by Google Enhanced Safe Browsing with {user_txt} and {intel.get('rating', 'high')}/5.0 rating."
        elif score >= 60:
            verdict = "ESTABLISHED_COMMUNITY"
            summary = f"Established extension with {intel.get('users_count', 'active community')} and positive reputation metrics."
        elif score >= 40:
            verdict = "MODERATE_REPUTATION"
            summary = f"Extension listed with moderate adoption ({intel.get('users_count', 'few users')})."
        else:
            verdict = "LOW_ADOPTION_OR_UNRATED"
            summary = "Extension has limited community adoption or unvetted developer track record."

        intel["reputation_score"] = min(100, max(0, score))
        intel["reputation_verdict"] = verdict
        intel["reputation_summary"] = summary

        return intel

    @classmethod
    def _extract_zip_bytes(cls, file_path: Path) -> Tuple[Optional[bytes], Optional[int]]:
        """Extracts ZIP archive from CRX2/CRX3 or returns raw bytes if already ZIP."""
        with open(file_path, "rb") as f:
            data = f.read()

        if data.startswith(b"PK\x03\x04"):
            return data, None

        if data.startswith(b"Cr24"):
            if len(data) < 16:
                return None, None
            # Read version
            import struct
            version = struct.unpack("<I", data[4:8])[0]
            if version == 2:
                # CRX2: 4 bytes magic, 4 bytes version, 4 bytes pubkey_len, 4 bytes sig_len
                pubkey_len, sig_len = struct.unpack("<II", data[8:16])
                zip_start = 16 + pubkey_len + sig_len
                if zip_start < len(data):
                    return data[zip_start:], 2
            elif version == 3:
                # CRX3: 4 bytes magic, 4 bytes version, 4 bytes header_size
                header_size = struct.unpack("<I", data[8:12])[0]
                zip_start = 12 + header_size
                if zip_start < len(data):
                    return data[zip_start:], 3

            # Fallback: search for PK\x03\x04 signature
            idx = data.find(b"PK\x03\x04")
            if idx != -1:
                return data[idx:], version

        return None, None

    @classmethod
    def _read_manifest(cls, zf: zipfile.ZipFile) -> Optional[Dict[str, Any]]:
        """Finds and decodes manifest.json."""
        target_name = None
        for n in zf.namelist():
            if n.lower() == "manifest.json" or n.lower().endswith("/manifest.json"):
                target_name = n
                break
        if not target_name:
            return None

        try:
            raw = zf.read(target_name).decode("utf-8", errors="replace")
            # 1. Try standard JSON parse first (preserves URLs with // such as *://*/* and https://)
            try:
                return json.loads(raw, strict=False)
            except Exception:
                pass

            # 2. Clean single-line comments safely without corrupting URLs
            cleaned = re.sub(r'^\s*//.*$', '', raw, flags=re.MULTILINE)
            cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL)
            try:
                return json.loads(cleaned, strict=False)
            except Exception:
                # 3. Clean trailing commas before } or ]
                cleaned = re.sub(r',(\s*[}\]])', r'\1', cleaned)
                return json.loads(cleaned, strict=False)
        except Exception as e:
            logger.debug(f"Failed to parse manifest.json: {e}")
            return None

    @classmethod
    def _parse_manifest_metadata(cls, manifest: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Parses permissions, background tasks, content scripts, and CSP."""
        result["name"] = manifest.get("name", "Unknown Extension")
        result["version"] = manifest.get("version", "0.0.0")
        result["description"] = manifest.get("description", "")
        result["author"] = manifest.get("author", "")
        result["homepage_url"] = manifest.get("homepage_url", "")
        result["update_url"] = manifest.get("update_url", "")
        result["manifest_version"] = manifest.get("manifest_version", 2)

        # 1. Permissions parsing
        raw_perms = manifest.get("permissions", []) or []
        optional_perms = manifest.get("optional_permissions", []) or []
        host_perms = manifest.get("host_permissions", []) or []

        all_perms = list(set(raw_perms + optional_perms))
        for p in all_perms:
            if not isinstance(p, str):
                continue
            p_lower = p.strip().lower()

            # Check if host pattern
            if "://" in p_lower or p_lower == "<all_urls>":
                result["permissions"]["host_permissions"].append(p)
                if p_lower in CRITICAL_PERMISSIONS:
                    result["permissions"]["critical"].append({"permission": p, "description": CRITICAL_PERMISSIONS[p_lower]})
                else:
                    result["permissions"]["high"].append({"permission": p, "description": "Host access permission to match pattern"})
                continue

            if p_lower in CRITICAL_PERMISSIONS:
                result["permissions"]["critical"].append({"permission": p, "description": CRITICAL_PERMISSIONS[p_lower]})
            elif p_lower in HIGH_PERMISSIONS:
                result["permissions"]["high"].append({"permission": p, "description": HIGH_PERMISSIONS[p_lower]})
            elif p_lower in MEDIUM_PERMISSIONS:
                result["permissions"]["medium"].append({"permission": p, "description": MEDIUM_PERMISSIONS[p_lower]})
            else:
                result["permissions"]["low"].append({"permission": p, "description": "Standard low-risk permission"})

        for hp in host_perms:
            if isinstance(hp, str) and hp not in result["permissions"]["host_permissions"]:
                result["permissions"]["host_permissions"].append(hp)
                if hp.lower() in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
                    result["permissions"]["critical"].append({"permission": hp, "description": "Unrestricted broad host access"})
                else:
                    result["permissions"]["high"].append({"permission": hp, "description": f"Host permission to {hp}"})

        # 2. Background worker inspection
        bg = manifest.get("background", {})
        if isinstance(bg, dict):
            if bg.get("service_worker"):
                result["background"]["has_background"] = True
                result["background"]["service_worker"] = bg.get("service_worker")
            if bg.get("scripts"):
                result["background"]["has_background"] = True
                result["background"]["scripts"] = bg.get("scripts", [])
            if bg.get("persistent") is True:
                result["background"]["is_persistent"] = True
                result["risk_flags"].append({
                    "severity": "medium",
                    "title": "Persistent Background Script Execution",
                    "description": "Extension runs continuously in the background consuming memory and monitoring activity."
                })

        # 3. Content scripts inspection
        content_scripts = manifest.get("content_scripts", [])
        if isinstance(content_scripts, list):
            for cs in content_scripts:
                if isinstance(cs, dict):
                    matches = cs.get("matches", [])
                    js_files = cs.get("js", [])
                    run_at = cs.get("run_at", "document_idle")
                    result["content_scripts"].append({
                        "matches": matches,
                        "js": js_files,
                        "run_at": run_at
                    })
                    if any(m in ("<all_urls>", "*://*/*") for m in matches):
                        result["risk_flags"].append({
                            "severity": "high",
                            "title": "Content Script Injected on All Websites",
                            "description": f"Injected files {js_files} execute on all visited websites (<all_urls>)."
                        })

        # 4. Content Security Policy (CSP)
        csp = manifest.get("content_security_policy")
        csp_str = ""
        if isinstance(csp, str):
            csp_str = csp
        elif isinstance(csp, dict):
            csp_str = csp.get("extension_pages", "") or csp.get("sandbox", "")

        result["csp"]["raw"] = csp_str
        if csp_str:
            csp_lower = csp_str.lower()
            if "'unsafe-eval'" in csp_lower:
                result["csp"]["allows_unsafe_eval"] = True
                result["risk_flags"].append({
                    "severity": "high",
                    "title": "Insecure CSP: unsafe-eval Permitted",
                    "description": "CSP permits eval() and dynamic code generation, allowing potential arbitrary code execution."
                })
            if "'unsafe-inline'" in csp_lower:
                result["csp"]["allows_unsafe_inline"] = True
                result["risk_flags"].append({
                    "severity": "medium",
                    "title": "Insecure CSP: unsafe-inline Permitted",
                    "description": "CSP allows inline scripts, weakening XSS defenses."
                })
            if "http://" in csp_lower or "https://" in csp_lower:
                result["csp"]["allows_remote_scripts"] = True
                result["risk_flags"].append({
                    "severity": "high",
                    "title": "Insecure CSP: Remote Script Loading",
                    "description": "CSP references external remote origins for executable scripts."
                })

    @classmethod
    def _scan_extension_scripts(cls, zf: zipfile.ZipFile, result: Dict[str, Any]) -> None:
        """Scans JavaScript files inside extension for malicious patterns."""
        js_files = [n for n in zf.namelist() if n.lower().endswith(".js")]

        for js_name in js_files[:50]:  # Limit to 50 files for safety
            try:
                content = zf.read(js_name).decode("utf-8", errors="ignore")
                for regex, title, severity, mitre in JS_SUSPICIOUS_PATTERNS:
                    matches = list(regex.finditer(content))
                    if matches:
                        match_count = len(matches)
                        # Extract first sample snippet
                        first_match = matches[0]
                        start = max(0, first_match.start() - 30)
                        end = min(len(content), first_match.end() + 30)
                        snippet = content[start:end].replace('\n', ' ').strip()

                        result["js_findings"].append({
                            "file": js_name,
                            "title": title,
                            "severity": severity,
                            "mitre": mitre,
                            "occurrences": match_count,
                            "snippet": snippet[:100]
                        })
            except Exception as e:
                logger.debug(f"Error scanning JS file {js_name}: {e}")

    @classmethod
    def _calculate_risk_score(cls, result: Dict[str, Any]) -> None:
        """Computes risk score (0-100) and risk level."""
        score = 0

        # Critical permissions: +25 each
        score += len(result["permissions"]["critical"]) * 25
        # High permissions: +12 each
        score += len(result["permissions"]["high"]) * 12
        # Medium permissions: +5 each
        score += len(result["permissions"]["medium"]) * 5

        # Insecure CSP
        if result["csp"]["allows_unsafe_eval"]:
            score += 20
        if result["csp"]["allows_remote_scripts"]:
            score += 20

        # JS findings
        for f in result["js_findings"]:
            sev = f.get("severity")
            if sev == "CRITICAL":
                score += 25
            elif sev == "HIGH":
                score += 15
            elif sev == "MEDIUM":
                score += 5

        # Cap score at 100
        score = min(100, score)
        result["risk_score"] = score

        if score >= 60:
            result["risk_level"] = "CRITICAL" if score >= 80 else "HIGH RISK"
        elif score >= 35:
            result["risk_level"] = "MEDIUM RISK"
        elif score > 0:
            result["risk_level"] = "LOW RISK"
        else:
            result["risk_level"] = "CLEAN"

        summary = f"Extension '{result['name']}' (v{result['version']}) evaluated as {result['risk_level']} (Score: {score}/100). "
        if result["permissions"]["critical"]:
            summary += f"Requests {len(result['permissions']['critical'])} CRITICAL permission(s). "
        if result["js_findings"]:
            summary += f"Identified {len(result['js_findings'])} heuristic security alert(s) in bundled JavaScript code."
        result["summary"] = summary
