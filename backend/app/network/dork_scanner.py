"""
Automated Google Dorks & Sensitive Artifact Discovery Engine.
Automates passive and targeted reconnaissance across target domains to discover:
- Confidential & Internal Documents (.pdf, .docx, .xlsx, .doc, .xls, .pptx)
- Credentials & Configuration Secrets (.env, .git/config, .yml, .json, .key, .pem)
- Database Dumps & Backup Archives (.sql, .dump, .bak, .backup, .tar.gz, .zip)
- Exposed Server Logs & Traces (.log, access.log, error.log)
- Administrative & Management Consoles (/admin, /login, /portal, /cpanel)

Parses discovered URLs, classifies artifacts by severity and risk, and compiles
interactive, pre-built Google Dork launchpads for security analysts.
"""

from typing import Dict, Any, List, Optional, Set, Tuple
import urllib.parse
import re
from pathlib import Path
import httpx
from bs4 import BeautifulSoup

from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


# Artifact category definitions & regex matchers
SENSITIVE_EXTENSIONS = {
    "document": [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".rtf", ".csv"],
    "secret": [".env", ".key", ".pem", ".pfx", ".p12", ".crt", ".conf", ".cnf", ".ini", ".cfg"],
    "database": [".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".bak", ".backup", ".old", ".tar.gz", ".zip", ".7z", ".tar"],
    "log": [".log", ".out", ".err", ".trace"]
}

CONFIDENTIAL_KEYWORDS = [
    "confidential", "internal use only", "not for public", "privileged", "strictly private",
    "proprietary", "salary", "payroll", "budget", "board meeting", "credential", "password",
    "secret", "nda", "classified", "restricted"
]

COMMON_SENSITIVE_PROBE_PATHS = [
    ("/.env", "secret", "critical", "Environment & Secrets Configuration File", r"(?i)(APP_KEY|DB_PASSWORD|SECRET_KEY|API_KEY|AWS_)"),
    ("/.git/config", "secret", "critical", "Exposed Git Source Code Repository", r"\[core\]"),
    ("/.git/HEAD", "secret", "critical", "Exposed Git HEAD Reference", r"ref:\s+refs/"),
    ("/backup.sql", "database", "critical", "Exposed SQL Database Dump", r"(?i)(CREATE\s+TABLE|INSERT\s+INTO|mysqldump|pg_dump)"),
    ("/dump.sql", "database", "critical", "Exposed SQL Database Dump", r"(?i)(CREATE\s+TABLE|INSERT\s+INTO)"),
    ("/db.sql", "database", "critical", "Exposed Database Schema & Data", r"(?i)(CREATE\s+TABLE|INSERT\s+INTO)"),
    ("/backup.zip", "database", "high", "Exposed Backup Archive (ZIP)", None),
    ("/web.config", "secret", "high", "IIS Web Server Configuration File", r"<configuration>"),
    ("/error.log", "log", "medium", "Exposed Server Application Error Log", r"(?i)(error|exception|stack\s*trace)"),
    ("/access.log", "log", "medium", "Exposed HTTP Web Server Access Log", None),
    ("/id_rsa", "secret", "critical", "Exposed OpenSSH Private Key", r"BEGIN\s+(RSA\s+)?PRIVATE\s+KEY"),
    ("/id_rsa.pub", "secret", "medium", "Exposed OpenSSH Public Key", r"ssh-(rsa|ed25519)"),
    ("/composer.json", "secret", "low", "PHP Dependency & Project Descriptor", r"\"require\""),
    ("/package.json", "secret", "low", "Node.js Dependency & Project Descriptor", r"\"dependencies\""),
]


class DorkArtifactScanner:
    """
    Automated scanner for public documents, exposed files, and Google Dork findings.
    """

    @classmethod
    def generate_dork_presets(cls, target_domain: str) -> List[Dict[str, Any]]:
        """
        Builds curated, ready-to-run Google Dork queries targeted to the domain.
        """
        domain = target_domain.strip().lower()
        presets = [
            {
                "id": "dork_documents",
                "title": "Public & Corporate Documents",
                "category": "Documents",
                "query": f'site:{domain} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:doc OR filetype:xls)',
                "description": "Searches for indexed enterprise PDF reports, Word documents, and Excel spreadsheets."
            },
            {
                "id": "dork_confidential",
                "title": "Confidential & Restricted Markings",
                "category": "Confidential",
                "query": f'site:{domain} (filetype:pdf OR filetype:docx) ("confidential" OR "internal use only" OR "proprietary" OR "privileged")',
                "description": "Locates documents containing confidential, proprietary, or internal-only classification markings."
            },
            {
                "id": "dork_secrets",
                "title": "Configuration & Environment Secrets",
                "category": "Secrets",
                "query": f'site:{domain} (ext:env OR ext:yml OR ext:yaml OR ext:conf OR ext:cnf OR ext:ini) ("password" OR "api_key" OR "secret" OR "database")',
                "description": "Finds exposed server configuration files, environment files (.env), and credentials."
            },
            {
                "id": "dork_backups",
                "title": "Database Dumps & Backup Archives",
                "category": "Backups",
                "query": f'site:{domain} (ext:sql OR ext:dump OR ext:bak OR ext:backup OR ext:tar.gz OR ext:7z)',
                "description": "Discovers leaked SQL database backups, archive snapshots, and temporary dump files."
            },
            {
                "id": "dork_logs",
                "title": "Exposed Server & Debug Logs",
                "category": "Logs",
                "query": f'site:{domain} ext:log ("error" OR "exception" OR "warning" OR "stack trace")',
                "description": "Searches for web server and application debug traces containing system internals."
            },
            {
                "id": "dork_portals",
                "title": "Admin & Login Consoles",
                "category": "Portals",
                "query": f'site:{domain} (inurl:admin OR inurl:login OR inurl:portal OR inurl:dashboard OR inurl:cpanel)',
                "description": "Enumerates exposed management panels, admin dashboards, and employee login portals."
            },
            {
                "id": "dork_indexes",
                "title": "Open Directory Listings (Index of /)",
                "category": "Directories",
                "query": f'site:{domain} (intitle:"index of /" OR intitle:"index.of")',
                "description": "Detects web servers with directory indexing enabled, exposing browsing of raw folders."
            }
        ]

        for p in presets:
            p["google_url"] = f"https://www.google.com/search?q={urllib.parse.quote(p['query'])}"

        return presets

    @classmethod
    def scan(cls, target: str, is_ip: bool = False, max_results: int = 50) -> Dict[str, Any]:
        """
        Executes automated sensitive artifact and document discovery for a target.
        """
        clean_target = target.strip().lower().rstrip("/")
        if "://" in clean_target:
            clean_target = clean_target.split("://", 1)[1].split("/", 1)[0]
        clean_target = clean_target.split(":", 1)[0]

        presets = cls.generate_dork_presets(clean_target)

        result: Dict[str, Any] = {
            "target": clean_target,
            "scanned": True,
            "total_artifacts_found": 0,
            "category_counts": {
                "documents": 0,
                "secrets": 0,
                "databases": 0,
                "logs": 0,
                "admin": 0
            },
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "artifacts": [],
            "dork_presets": presets,
            "summary": "Automated document and sensitive artifact scan completed."
        }

        if not clean_target or len(clean_target) < 3:
            return result

        discovered_artifacts: List[Dict[str, Any]] = []
        seen_urls: Set[str] = set()

        # 1. Safe Direct Sensitive File Prober (Non-intrusive HEAD/GET)
        cls._probe_common_sensitive_paths(clean_target, discovered_artifacts, seen_urls)

        # 2. Extract Document & Sensitive Links from Robots.txt and Sitemap.xml
        cls._extract_from_sitemaps_and_robots(clean_target, discovered_artifacts, seen_urls)

        # 3. Query Public Search Engine Dorks (DuckDuckGo HTML query)
        if not is_ip:
            cls._query_search_dorks(clean_target, discovered_artifacts, seen_urls)

        # Classify, count, and format results
        for idx, art in enumerate(discovered_artifacts[:max_results]):
            art["id"] = f"art_{idx + 1}"
            result["artifacts"].append(art)

            cat = art.get("category", "document")
            if cat in ("document", "documents"):
                result["category_counts"]["documents"] += 1
            elif cat in ("secret", "secrets"):
                result["category_counts"]["secrets"] += 1
            elif cat in ("database", "databases", "backup", "backups"):
                result["category_counts"]["databases"] += 1
            elif cat in ("log", "logs"):
                result["category_counts"]["logs"] += 1
            elif cat in ("admin", "portal", "portals"):
                result["category_counts"]["admin"] += 1

            sev = art.get("severity", "low").lower()
            if sev in result["severity_counts"]:
                result["severity_counts"][sev] += 1

        result["total_artifacts_found"] = len(result["artifacts"])
        result["summary"] = (
            f"Discovered {result['total_artifacts_found']} sensitive artifact(s) across target infrastructure: "
            f"{result['category_counts']['documents']} document(s), "
            f"{result['category_counts']['secrets']} secret/config(s), "
            f"{result['category_counts']['databases']} database/backup(s), "
            f"{result['category_counts']['logs']} server log(s)."
        )

        return result

    @classmethod
    def _probe_common_sensitive_paths(
        cls, target: str, artifacts: List[Dict[str, Any]], seen_urls: Set[str]
    ) -> None:
        """
        Tests standard sensitive endpoints with SSRF guard.
        """
        is_safe, _, _ = validate_url_for_ssrf(f"http://{target}")
        if not is_safe:
            return

        headers = {
            "User-Agent": "FileSanitizer-SecurityScanner/1.0",
            "Accept": "*/*"
        }

        # Check HTTPS then HTTP
        protocols = ["https://", "http://"]

        with httpx.Client(timeout=2.5, follow_redirects=True, headers=headers) as client:
            base_proto = None
            for p in protocols:
                try:
                    r = client.get(f"{p}{target}/", timeout=2.0)
                    if r.status_code < 500:
                        base_proto = p
                        break
                except Exception:
                    pass

            if not base_proto:
                return

            for path, category, severity, label, pattern in COMMON_SENSITIVE_PROBE_PATHS:
                test_url = f"{base_proto}{target}{path}"
                if test_url in seen_urls:
                    continue

                try:
                    resp = client.get(test_url)
                    if resp.status_code == 200:
                        body_sample = resp.text[:4096]
                        content_len = len(resp.content)
                        # Avoid soft 404 or custom error pages that return 200 with generic HTML
                        is_html = "text/html" in resp.headers.get("content-type", "").lower()
                        if is_html and path in ("/.env", "/.git/config", "/backup.sql", "/error.log", "/id_rsa"):
                            # Must match pattern if it claims to be HTML
                            if pattern and not re.search(pattern, body_sample):
                                continue

                        if pattern and not re.search(pattern, body_sample):
                            continue

                        # Minimum content check
                        if content_len > 10:
                            seen_urls.add(test_url)
                            fname = Path(path).name or path
                            ext = Path(path).suffix or ".txt"

                            artifacts.append({
                                "url": test_url,
                                "filename": fname,
                                "extension": ext.lower(),
                                "title": f"Exposed {fname} ({label})",
                                "category": category,
                                "category_label": label,
                                "severity": severity,
                                "source": "Direct Path Exposure Audit",
                                "snippet": body_sample[:180].strip() if body_sample else f"File reachable with HTTP 200 ({content_len} bytes)",
                                "status_code": resp.status_code
                            })
                except Exception:
                    pass

    @classmethod
    def _extract_from_sitemaps_and_robots(
        cls, target: str, artifacts: List[Dict[str, Any]], seen_urls: Set[str]
    ) -> None:
        """
        Parses declared links in robots.txt and sitemap.xml for document extensions.
        """
        is_safe, _, _ = validate_url_for_ssrf(f"http://{target}")
        if not is_safe:
            return

        headers = {"User-Agent": "FileSanitizer-SecurityScanner/1.0"}

        with httpx.Client(timeout=3.0, follow_redirects=True, headers=headers) as client:
            candidate_files = [f"https://{target}/robots.txt", f"https://{target}/sitemap.xml"]
            for curl in candidate_files:
                try:
                    resp = client.get(curl)
                    if resp.status_code == 200 and resp.text:
                        text = resp.text
                        # Extract URLs and paths
                        found_paths = re.findall(r"(?:https?://[^\s\"'<>]+|/[A-Za-z0-9_./-]+\.[a-zA-Z0-9]{2,5})", text)
                        for item in found_paths:
                            full_url = item if item.startswith("http") else f"https://{target}{item}"
                            if full_url in seen_urls:
                                continue

                            ext = Path(urllib.parse.urlparse(full_url).path).suffix.lower()
                            cat, sev, label = cls._classify_extension(ext, full_url)
                            if cat:
                                seen_urls.add(full_url)
                                fname = Path(urllib.parse.urlparse(full_url).path).name
                                artifacts.append({
                                    "url": full_url,
                                    "filename": fname,
                                    "extension": ext,
                                    "title": fname or full_url,
                                    "category": cat,
                                    "category_label": label,
                                    "severity": sev,
                                    "source": "Robots / Sitemap Inspection",
                                    "snippet": f"Referenced in {Path(curl).name}",
                                    "status_code": 200
                                })
                except Exception:
                    pass

    @classmethod
    def _query_search_dorks(
        cls, domain: str, artifacts: List[Dict[str, Any]], seen_urls: Set[str]
    ) -> None:
        """
        Queries DuckDuckGo HTML search for documents and files.
        """
        queries = [
            (f"site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx", "document"),
            (f"site:{domain} ext:env OR ext:sql OR ext:bak OR ext:log", "secret")
        ]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }

        try:
            with httpx.Client(timeout=4.5, headers=headers) as client:
                for q_str, default_cat in queries:
                    try:
                        r = client.post("https://html.duckduckgo.com/html/", data={"q": q_str})
                        if r.status_code == 200:
                            soup = BeautifulSoup(r.text, "html.parser")
                            for res in soup.select(".result"):
                                if "result--ad" in res.get("class", []):
                                    continue
                                url_elem = res.select_one(".result__url")
                                title_elem = res.select_one(".result__title")
                                snippet_elem = res.select_one(".result__snippet")

                                if url_elem and title_elem:
                                    raw_url = url_elem.get_text(strip=True)
                                    if not raw_url.startswith("http"):
                                        raw_url = "https://" + raw_url

                                    if domain in raw_url and raw_url not in seen_urls:
                                        seen_urls.add(raw_url)
                                        parsed_path = urllib.parse.urlparse(raw_url).path
                                        ext = Path(parsed_path).suffix.lower()
                                        fname = Path(parsed_path).name or "document"
                                        title = title_elem.get_text(strip=True)
                                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""

                                        cat, sev, label = cls._classify_extension(ext, raw_url, snippet)
                                        artifacts.append({
                                            "url": raw_url,
                                            "filename": fname,
                                            "extension": ext or ".file",
                                            "title": title,
                                            "category": cat or default_cat,
                                            "category_label": label,
                                            "severity": sev,
                                            "source": "Search Dork Engine",
                                            "snippet": snippet,
                                            "matched_dork": q_str
                                        })
                    except Exception as e:
                        logger.debug(f"DuckDuckGo search error for {q_str}: {e}")
        except Exception:
            pass

    @classmethod
    def _classify_extension(
        cls, ext: str, url: str = "", snippet: str = ""
    ) -> Tuple[Optional[str], str, str]:
        """
        Determines category, severity, and label for an artifact.
        """
        combined = f"{url.lower()} {snippet.lower()}"
        ext_clean = ext.lower().strip()

        # 1. Secrets / Credentials
        if ext_clean in SENSITIVE_EXTENSIONS["secret"] or ".env" in combined or "id_rsa" in combined:
            return "secret", "critical", "Credentials & Configuration Secret"

        # 2. Database Dumps
        if ext_clean in (".sql", ".dump", ".db", ".sqlite", ".sqlite3"):
            return "database", "critical", "Database Dump & Schema"

        # 3. Backups & Archives
        if ext_clean in (".bak", ".backup", ".old", ".tar.gz", ".7z", ".zip", ".tar"):
            return "database", "high", "Backup Archive / Snapshot"

        # 4. Logs
        if ext_clean in SENSITIVE_EXTENSIONS["log"]:
            return "log", "medium", "Server Log / Diagnostic Trace"

        # 5. Documents
        if ext_clean in SENSITIVE_EXTENSIONS["document"]:
            # Check for confidential markings in snippet/URL
            if any(k in combined for k in CONFIDENTIAL_KEYWORDS):
                return "document", "high", "Confidential / Internal Document"
            elif ext_clean in (".xlsx", ".xls"):
                return "document", "medium", "Spreadsheet / Financial Data"
            return "document", "low", "Public Document / Presentation"

        return None, "low", "File"
