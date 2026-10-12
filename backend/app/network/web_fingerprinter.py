"""
Web Technology, Redirection Chain & Asset Fingerprinter.
Collects: HTTP response headers, security headers compliance grade, Favicon MurmurHash3 (Shodan-compatible),
external script & iframe dependencies, analytics tracking IDs, and login form harvesting detection.
Traces: Complete redirection hops (3xx, meta refresh, JS) with per-hop SSRF validation.
"""

import re
import codecs
import urllib.parse
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional, Tuple
import httpx

from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


def murmurhash3_32(key: bytes, seed: int = 0) -> int:
    """
    Pure Python 32-bit MurmurHash3 implementation matching mmh3.hash().
    Produces signed 32-bit integers identical to Shodan's favicon hash.
    """
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(key)
    h1 = seed
    nblocks = length // 4

    for i in range(nblocks):
        k1 = int.from_bytes(key[4 * i : 4 * i + 4], byteorder='little')
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = key[nblocks * 4 :]
    k1 = 0
    tail_len = len(tail)
    if tail_len >= 3:
        k1 ^= tail[2] << 16
    if tail_len >= 2:
        k1 ^= tail[1] << 8
    if tail_len >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit integer matching Shodan mmh3.hash()
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


class WebFingerprinter:
    """
    Traces web redirects and fingerprints web assets, headers, security policies, and HTML structures.
    """

    @classmethod
    def fingerprint(cls, initial_url: str, max_hops: int = 5) -> Dict[str, Any]:
        """
        Follows redirection hops safely, captures headers, evaluates security grades,
        downloads and hashes favicon, and analyzes DOM dependencies.
        """
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', initial_url):
            current_url = f"https://{initial_url}"
        else:
            current_url = initial_url

        result: Dict[str, Any] = {
            "initial_url": initial_url,
            "final_url": current_url,
            "status_code": None,
            "redirect_chain": [],
            "hop_count": 0,
            "response_headers": {},
            "server_technology": None,
            "powered_by": None,
            "security_headers": {
                "grade": "F",
                "score": 0,
                "hsts": {"present": False, "value": None},
                "csp": {"present": False, "value": None},
                "x_frame_options": {"present": False, "value": None},
                "x_content_type_options": {"present": False, "value": None},
                "referrer_policy": {"present": False, "value": None},
                "permissions_policy": {"present": False, "value": None},
                "recommendations": []
            },
            "favicon": {
                "found": False,
                "url": None,
                "murmur_hash": None,
                "md5": None,
                "shodan_query": None
            },
            "dom_analysis": {
                "title": None,
                "has_login_form": False,
                "login_form_actions": [],
                "external_scripts": [],
                "external_iframes": [],
                "analytics_ids": []
            },
            "findings": []
        }

        # Follow redirects with per-hop SSRF validation
        redirect_chain: List[Dict[str, Any]] = []
        hop = 0
        final_content = b""
        final_headers: Dict[str, str] = {}
        headers_to_send = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        }

        with httpx.Client(timeout=6.0, verify=False, follow_redirects=False) as client:
            while hop <= max_hops:
                # SSRF check before each hop
                is_safe, ssrf_reason, _ = validate_url_for_ssrf(current_url)
                if not is_safe:
                    result["findings"].append({
                        "severity": "critical",
                        "title": "Redirect Blocked by SSRF Policy",
                        "description": f"Hop {hop} attempted to navigate to blocked internal address: {ssrf_reason}"
                    })
                    break

                try:
                    resp = client.get(current_url, headers=headers_to_send)
                    status = resp.status_code
                    final_headers = {k.lower(): v for k, v in resp.headers.items()}
                    final_content = resp.content

                    redirect_chain.append({
                        "hop": hop,
                        "url": current_url,
                        "status_code": status,
                        "location": resp.headers.get("location")
                    })

                    if status in (301, 302, 303, 307, 308) and "location" in resp.headers:
                        loc = resp.headers["location"]
                        current_url = urllib.parse.urljoin(current_url, loc)
                        hop += 1
                        continue

                    # Check for meta refresh or JS redirect in HTML body if status is 200
                    if status == 200 and b"<html" in final_content.lower() and hop < max_hops:
                        meta_url = cls._extract_meta_refresh(final_content, current_url)
                        if meta_url and meta_url != current_url:
                            redirect_chain.append({
                                "hop": hop,
                                "url": current_url,
                                "status_code": "META_REFRESH",
                                "location": meta_url
                            })
                            current_url = meta_url
                            hop += 1
                            continue

                    result["status_code"] = status
                    result["final_url"] = current_url
                    result["hop_count"] = hop
                    break

                except Exception as e:
                    logger.debug(f"HTTP request error during fingerprinting {current_url}: {e}")
                    break

        result["redirect_chain"] = redirect_chain
        result["response_headers"] = final_headers

        if hop > 0:
            initial_domain = urllib.parse.urlparse(initial_url).netloc
            final_domain = urllib.parse.urlparse(result["final_url"]).netloc
            if initial_domain and final_domain and initial_domain != final_domain:
                result["findings"].append({
                    "severity": "medium",
                    "title": f"Cross-Domain Redirection ({initial_domain} -> {final_domain})",
                    "description": f"URL traversed {hop} redirection hop(s) and landed on a distinct domain."
                })

        # Evaluate Server & Powered-By
        if "server" in final_headers:
            result["server_technology"] = final_headers["server"]
        if "x-powered-by" in final_headers:
            result["powered_by"] = final_headers["x-powered-by"]

        # Evaluate Security Headers
        cls._evaluate_security_headers(final_headers, result)

        # Parse DOM content
        if final_content and b"<html" in final_content.lower():
            cls._analyze_html_dom(final_content, result["final_url"], result)

        # Fetch and fingerprint Favicon (Shodan MurmurHash3)
        cls._fingerprint_favicon(result["final_url"], final_content, client, result)

        return result

    @classmethod
    def _extract_meta_refresh(cls, content: bytes, base_url: str) -> Optional[str]:
        """Extracts destination URL from <meta http-equiv='refresh' content='...'>."""
        try:
            soup = BeautifulSoup(content[:10000], "html.parser")
            meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
            if meta and meta.get("content"):
                match = re.search(r'url\s*=\s*([^;]+)', meta["content"], re.I)
                if match:
                    dest = match.group(1).strip().strip('"\'')
                    return urllib.parse.urljoin(base_url, dest)
        except Exception:
            pass
        return None

    @classmethod
    def _evaluate_security_headers(cls, headers: Dict[str, str], result: Dict[str, Any]) -> None:
        """
        Grades HTTP security headers from A+ to F with actionable remediation guidance.
        """
        sec = result["security_headers"]
        score = 0
        recs = []

        # 1. HSTS
        hsts_val = headers.get("strict-transport-security")
        if hsts_val:
            sec["hsts"] = {"present": True, "value": hsts_val}
            score += 25
            if "preload" in hsts_val and "includesubdomains" in hsts_val.lower():
                score += 5
        else:
            recs.append("Enable HTTP Strict Transport Security (HSTS) with includeSubDomains")

        # 2. CSP
        csp_val = headers.get("content-security-policy")
        if csp_val:
            sec["csp"] = {"present": True, "value": csp_val[:120]}
            score += 30
        else:
            recs.append("Deploy Content-Security-Policy (CSP) to mitigate Cross-Site Scripting (XSS)")

        # 3. X-Frame-Options
        xfo_val = headers.get("x-frame-options")
        if xfo_val:
            sec["x_frame_options"] = {"present": True, "value": xfo_val}
            score += 15
        else:
            recs.append("Configure X-Frame-Options (DENY or SAMEORIGIN) to prevent Clickjacking")

        # 4. X-Content-Type-Options
        xcto_val = headers.get("x-content-type-options")
        if xcto_val and "nosniff" in xcto_val.lower():
            sec["x_content_type_options"] = {"present": True, "value": xcto_val}
            score += 15
        else:
            recs.append("Add X-Content-Type-Options: nosniff to prevent MIME confusion attacks")

        # 5. Referrer-Policy
        ref_val = headers.get("referrer-policy")
        if ref_val:
            sec["referrer_policy"] = {"present": True, "value": ref_val}
            score += 10
        else:
            recs.append("Add Referrer-Policy (e.g. strict-origin-when-cross-origin)")

        # 6. Permissions-Policy
        perm_val = headers.get("permissions-policy")
        if perm_val:
            sec["permissions_policy"] = {"present": True, "value": perm_val[:100]}
            score += 5

        sec["score"] = min(100, score)
        sec["recommendations"] = recs

        if score >= 90:
            sec["grade"] = "A+"
        elif score >= 80:
            sec["grade"] = "A"
        elif score >= 65:
            sec["grade"] = "B"
        elif score >= 50:
            sec["grade"] = "C"
        elif score >= 35:
            sec["grade"] = "D"
        else:
            sec["grade"] = "F"

        if sec["grade"] in ("D", "F"):
            result["findings"].append({
                "severity": "low",
                "title": f"Poor Web Security Header Compliance (Grade {sec['grade']})",
                "description": f"Site scored {score}/100 on security header hardening. Missing critical defenses: {', '.join(recs[:3])}."
            })

    @classmethod
    def _analyze_html_dom(cls, content: bytes, base_url: str, result: Dict[str, Any]) -> None:
        """Parses HTML DOM for page title, external script/iframe links, login forms, and tracking IDs."""
        try:
            soup = BeautifulSoup(content, "html.parser")
            dom = result["dom_analysis"]

            # Title
            if soup.title and soup.title.string:
                dom["title"] = soup.title.string.strip()

            base_netloc = urllib.parse.urlparse(base_url).netloc.lower()

            # External scripts
            scripts = set()
            for s in soup.find_all("script", src=True):
                src = s["src"]
                full_src = urllib.parse.urljoin(base_url, src)
                parsed_src = urllib.parse.urlparse(full_src)
                if parsed_src.netloc and parsed_src.netloc.lower() != base_netloc:
                    scripts.add(parsed_src.netloc.lower())
            dom["external_scripts"] = sorted(list(scripts))[:20]

            # External iframes
            iframes = set()
            for f in soup.find_all("iframe", src=True):
                src = f["src"]
                full_src = urllib.parse.urljoin(base_url, src)
                parsed_f = urllib.parse.urlparse(full_src)
                if parsed_f.netloc and parsed_f.netloc.lower() != base_netloc:
                    iframes.add(parsed_f.netloc.lower())
            dom["external_iframes"] = sorted(list(iframes))[:10]

            # Login form / Credential harvesting detection
            login_forms = []
            for form in soup.find_all("form"):
                has_pass = form.find("input", attrs={"type": re.compile(r"^password$", re.I)})
                has_user = form.find("input", attrs={"name": re.compile(r"user|email|login|username", re.I)})
                if has_pass or has_user:
                    dom["has_login_form"] = True
                    action = form.get("action") or ""
                    full_action = urllib.parse.urljoin(base_url, action)
                    login_forms.append(full_action)

            dom["login_form_actions"] = login_forms
            if dom["has_login_form"]:
                result["findings"].append({
                    "severity": "medium",
                    "title": "Interactive Login / Credential Form Detected",
                    "description": f"Page contains authentication input fields. Form action: {login_forms[0] if login_forms else base_url}."
                })

            # Tracking & Analytics IDs
            text_str = content.decode("utf-8", errors="ignore")
            analytics_ids = set()
            for ga_match in re.findall(r'\b(UA-\d+-\d+|G-[A-Za-z0-9]+|GTM-[A-Za-z0-9]+)\b', text_str):
                analytics_ids.add(ga_match)
            dom["analytics_ids"] = sorted(list(analytics_ids))

        except Exception as e:
            logger.debug(f"HTML DOM parsing note for {base_url}: {e}")

    @classmethod
    def _fingerprint_favicon(cls, base_url: str, html_content: bytes, client: httpx.Client, result: Dict[str, Any]) -> None:
        """Downloads favicon and calculates Shodan-compatible MurmurHash3."""
        fav = result["favicon"]
        favicon_url = None

        # Look for <link rel="icon" ...> in HTML
        if html_content:
            try:
                soup = BeautifulSoup(html_content[:20000], "html.parser")
                icon_tag = soup.find("link", rel=lambda x: x and any(r in x.lower() for r in ["icon", "shortcut icon"]))
                if icon_tag and icon_tag.get("href"):
                    favicon_url = urllib.parse.urljoin(base_url, icon_tag["href"])
            except Exception:
                pass

        if not favicon_url:
            parsed = urllib.parse.urlparse(base_url)
            favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        try:
            is_safe, _, _ = validate_url_for_ssrf(favicon_url)
            if not is_safe:
                return

            resp = client.get(favicon_url, timeout=3.0)
            if resp.status_code == 200 and resp.content and len(resp.content) > 16:
                raw_bytes = resp.content
                import hashlib
                fav["found"] = True
                fav["url"] = favicon_url
                fav["md5"] = hashlib.md5(raw_bytes).hexdigest()

                # Shodan MurmurHash3 calculation:
                # Base64 with standard 76-character RFC 2045 line wraps including trailing \n
                b64_bytes = codecs.encode(raw_bytes, "base64")
                m_hash = murmurhash3_32(b64_bytes)
                fav["murmur_hash"] = m_hash
                fav["shodan_query"] = f"http.favicon.hash:{m_hash}"

        except Exception as e:
            logger.debug(f"Favicon fingerprinting note for {favicon_url}: {e}")

    @classmethod
    def compute_shodan_favicon_hash(cls, raw_bytes: bytes) -> int:
        """Calculates Shodan-compatible MurmurHash3_32 for raw favicon image bytes."""
        b64_bytes = codecs.encode(raw_bytes, "base64")
        return murmurhash3_32(b64_bytes)
