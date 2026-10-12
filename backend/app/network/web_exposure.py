"""
Passive Web Exposure & Asset Harvesting.
Safely retrieves and inspects /robots.txt, /sitemap.xml, and RFC 9116 security endpoints (/.well-known/).
Discovers administrative interfaces, backup directories, staging environments, API documentation,
and security contact policies without intrusive directory brute-forcing.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set
import httpx
import xml.etree.ElementTree as ET

from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


# Regex patterns matching sensitive or interesting paths in robots.txt / sitemaps
SENSITIVE_PATH_PATTERNS = [
    (r"(admin|administrator|adm|backend|panel|cpanel|controlpanel)", "Administrative Interface"),
    (r"(staging|stg|test|testing|dev|development|beta|qa|uat)", "Staging / Development Environment"),
    (r"(backup|backups|bak|dump|sql|db_dump|archive|snapshot)", "Database / Backup Archive"),
    (r"(logs?|logging|audit|access_log|error_log)", "Application / Server Logs"),
    (r"(api[_-]?docs?|swagger|openapi|redoc|graphql|graphiql)", "API & Schema Documentation"),
    (r"(config|configuration|settings|env|credentials|secret|keys?)", "Configuration & Secrets"),
    (r"(temp|tmp|old|legacy|portal|upload|internal)", "Internal / Temporary Storage"),
]


class WebExposureInspector:
    """
    Passive inspector for robots.txt, sitemap.xml, and well-known standards.
    """

    @classmethod
    def inspect(cls, target: str, port: int = 443, timeout_s: float = 4.0) -> Dict[str, Any]:
        """
        Inspects web exposure endpoints on target domain/hostname.
        """
        clean_target = target.strip().lower().rstrip("/")
        # Build base HTTPS URL with HTTP fallback
        base_urls = [
            f"https://{clean_target}:{port}" if port not in (80, 443) else f"https://{clean_target}",
            f"http://{clean_target}:{port}" if port not in (80, 443) else f"http://{clean_target}"
        ]

        result: Dict[str, Any] = {
            "target": clean_target,
            "has_exposure_data": False,
            "robots_txt": {
                "present": False,
                "url": None,
                "status_code": None,
                "disallowed_count": 0,
                "allowed_count": 0,
                "sitemaps_declared": [],
                "user_agents": [],
                "disallow_paths": [],
                "sensitive_paths_flagged": []
            },
            "sitemap_xml": {
                "present": False,
                "url": None,
                "status_code": None,
                "total_urls_found": 0,
                "sample_urls": [],
                "sensitive_routes_flagged": []
            },
            "well_known": {
                "security_txt": {"present": False, "url": None, "fields": {}, "contacts": []},
                "openid_configuration": {"present": False, "url": None, "issuer": None, "endpoints": {}},
                "assetlinks_json": {"present": False, "url": None, "package_names": []},
                "apple_app_site_association": {"present": False, "url": None, "app_ids": []}
            },
            "risk_flags": [],
            "positive_security_findings": []
        }

        # Try base URLs until one connects
        working_base = None
        for base in base_urls:
            is_safe, reason, _ = validate_url_for_ssrf(base)
            if not is_safe:
                logger.warning(f"SSRF validation blocked {base}: {reason}")
                continue
            working_base = base
            break

        if not working_base:
            return result

        with httpx.Client(timeout=timeout_s, follow_redirects=True, headers={"User-Agent": "FileSanitizer-HostAudit/1.0"}) as client:
            # 1. robots.txt
            cls._check_robots_txt(client, working_base, result)

            # 2. sitemap.xml
            cls._check_sitemap_xml(client, working_base, result)

            # 3. .well-known/ endpoints
            cls._check_well_known(client, working_base, result)

        if (
            result["robots_txt"]["present"]
            or result["sitemap_xml"]["present"]
            or any(v.get("present") for v in result["well_known"].values())
        ):
            result["has_exposure_data"] = True

        return result

    @classmethod
    def _check_robots_txt(cls, client: httpx.Client, base_url: str, result: Dict[str, Any]) -> None:
        robots_url = f"{base_url}/robots.txt"
        try:
            resp = client.get(robots_url)
            if resp.status_code == 200 and "text" in resp.headers.get("content-type", "").lower():
                body = resp.text
                # Guard against soft 404 HTML pages disguised as robots.txt
                if "<html" in body.lower() or "<body" in body.lower():
                    return

                result["robots_txt"]["present"] = True
                result["robots_txt"]["url"] = robots_url
                result["robots_txt"]["status_code"] = resp.status_code

                disallows: List[str] = []
                user_agents: Set[str] = set()
                sitemaps: List[str] = []

                for line in body.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "user-agent":
                            user_agents.add(v)
                        elif k == "disallow":
                            if v:
                                disallows.append(v)
                        elif k == "allow":
                            result["robots_txt"]["allowed_count"] += 1
                        elif k == "sitemap":
                            if v and v not in sitemaps:
                                sitemaps.append(v)

                result["robots_txt"]["disallowed_count"] = len(disallows)
                result["robots_txt"]["disallow_paths"] = disallows[:50]
                result["robots_txt"]["user_agents"] = list(user_agents)
                result["robots_txt"]["sitemaps_declared"] = sitemaps

                # Analyze disallowed paths for sensitive exposure
                flagged: List[Dict[str, str]] = []
                for p in disallows:
                    for pattern, category in SENSITIVE_PATH_PATTERNS:
                        if re.search(pattern, p, re.IGNORECASE):
                            flagged.append({"path": p, "category": category})
                            break

                result["robots_txt"]["sensitive_paths_flagged"] = flagged
                if flagged:
                    categories = list({f["category"] for f in flagged})
                    result["risk_flags"].append({
                        "severity": "medium",
                        "title": "Potentially Sensitive Paths Disclosed in robots.txt",
                        "description": f"Target's robots.txt explicitly enumerates {len(flagged)} sensitive path(s) ({', '.join(categories[:3])}). While intended for crawlers, these reveal internal administrative and staging routes to reconnaissance tools."
                    })
        except Exception as e:
            logger.debug(f"robots.txt check failed for {base_url}: {e}")

    @classmethod
    def _check_sitemap_xml(cls, client: httpx.Client, base_url: str, result: Dict[str, Any]) -> None:
        # Check declared sitemaps first, fallback to /sitemap.xml
        target_sitemaps = result["robots_txt"].get("sitemaps_declared") or [f"{base_url}/sitemap.xml"]
        for s_url in target_sitemaps[:2]:
            try:
                resp = client.get(s_url)
                if resp.status_code == 200 and ("xml" in resp.headers.get("content-type", "") or "<urlset" in resp.text or "<sitemapindex" in resp.text):
                    result["sitemap_xml"]["present"] = True
                    result["sitemap_xml"]["url"] = s_url
                    result["sitemap_xml"]["status_code"] = resp.status_code

                    # Safe XML parsing
                    root = ET.fromstring(resp.content[:500000])  # limit to 500KB
                    urls: List[str] = []
                    # Strip namespace if present
                    for elem in root.iter():
                        if elem.tag.endswith("loc") and elem.text:
                            loc = elem.text.strip()
                            if loc:
                                urls.append(loc)

                    result["sitemap_xml"]["total_urls_found"] = len(urls)
                    result["sitemap_xml"]["sample_urls"] = urls[:20]

                    # Check sensitive routes in sitemap
                    flagged: List[Dict[str, str]] = []
                    for u in urls[:50]:
                        for pattern, category in SENSITIVE_PATH_PATTERNS:
                            if re.search(pattern, u, re.IGNORECASE):
                                flagged.append({"url": u, "category": category})
                                break

                    result["sitemap_xml"]["sensitive_routes_flagged"] = flagged
                    if flagged:
                        result["risk_flags"].append({
                            "severity": "low",
                            "title": "Staging or Administrative URLs Indexed in sitemap.xml",
                            "description": f"Target's sitemap.xml exposes {len(flagged)} potentially sensitive URL(s) to public search engines."
                        })
                    break
            except Exception as e:
                logger.debug(f"sitemap.xml check failed for {s_url}: {e}")

    @classmethod
    def _check_well_known(cls, client: httpx.Client, base_url: str, result: Dict[str, Any]) -> None:
        # 1. /.well-known/security.txt (RFC 9116)
        sec_url = f"{base_url}/.well-known/security.txt"
        try:
            resp = client.get(sec_url)
            if resp.status_code == 200 and ("text" in resp.headers.get("content-type", "") or "Contact:" in resp.text):
                fields: Dict[str, List[str]] = {}
                contacts: List[str] = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        k, v = line.split(":", 1)
                        k = k.strip().capitalize()
                        v = v.strip()
                        fields.setdefault(k, []).append(v)
                        if k.lower() == "contact":
                            contacts.append(v)

                result["well_known"]["security_txt"]["present"] = True
                result["well_known"]["security_txt"]["url"] = sec_url
                result["well_known"]["security_txt"]["fields"] = fields
                result["well_known"]["security_txt"]["contacts"] = contacts
                result["positive_security_findings"].append({
                    "title": "RFC 9116 Vulnerability Disclosure Policy Published",
                    "description": f"Host publishes a valid security.txt policy defining authorized reporting channels ({', '.join(contacts[:2])})."
                })
        except Exception as e:
            logger.debug(f"security.txt check failed for {base_url}: {e}")

        # 2. /.well-known/openid-configuration
        oidc_url = f"{base_url}/.well-known/openid-configuration"
        try:
            resp = client.get(oidc_url)
            if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                data = resp.json()
                result["well_known"]["openid_configuration"]["present"] = True
                result["well_known"]["openid_configuration"]["url"] = oidc_url
                result["well_known"]["openid_configuration"]["issuer"] = data.get("issuer")
                result["well_known"]["openid_configuration"]["endpoints"] = {
                    "authorization": data.get("authorization_endpoint"),
                    "token": data.get("token_endpoint"),
                    "userinfo": data.get("userinfo_endpoint"),
                    "jwks_uri": data.get("jwks_uri")
                }
        except Exception as e:
            logger.debug(f"openid-configuration check failed for {base_url}: {e}")

        # 3. /.well-known/assetlinks.json (Android app links)
        asset_url = f"{base_url}/.well-known/assetlinks.json"
        try:
            resp = client.get(asset_url)
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                data = resp.json()
                pkgs: List[str] = []
                if isinstance(data, list):
                    for item in data:
                        target_info = item.get("target", {})
                        pkg = target_info.get("package_name")
                        if pkg and pkg not in pkgs:
                            pkgs.append(pkg)
                result["well_known"]["assetlinks_json"]["present"] = True
                result["well_known"]["assetlinks_json"]["url"] = asset_url
                result["well_known"]["assetlinks_json"]["package_names"] = pkgs
        except Exception as e:
            logger.debug(f"assetlinks.json check failed: {e}")

        # 4. /.well-known/apple-app-site-association (iOS Universal Links)
        apple_url = f"{base_url}/.well-known/apple-app-site-association"
        try:
            resp = client.get(apple_url)
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                data = resp.json()
                app_ids: List[str] = []
                applinks = data.get("applinks", {}).get("details", [])
                if isinstance(applinks, list):
                    for item in applinks:
                        aid = item.get("appID")
                        if aid and aid not in app_ids:
                            app_ids.append(aid)
                result["well_known"]["apple_app_site_association"]["present"] = True
                result["well_known"]["apple_app_site_association"]["url"] = apple_url
                result["well_known"]["apple_app_site_association"]["app_ids"] = app_ids
        except Exception as e:
            logger.debug(f"apple-app-site-association check failed: {e}")
