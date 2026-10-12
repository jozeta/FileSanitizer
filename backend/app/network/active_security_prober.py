"""
Active Security Reconnaissance & Vulnerability Prober.
Strictly opt-in, requires authorized=True, protected by SSRF validation and conservative timeouts.
Uses fast pre-flight connection checks and thread pool concurrency for high performance.

Capabilities:
- Sensitive Directory & Critical File Exposure Prober
- WAF & Reverse Proxy Detection / Evasion Fingerprinting
- CORS & HTTP Methods Misconfiguration Audit
- SSL/TLS Cryptographic Weakness & Deprecated Protocol Audit
- REST, OpenAPI & GraphQL API Endpoint Discovery
- Mail Server (SMTP) Open Relay & STARTTLS Verification
"""

import socket
import ssl
import re
import concurrent.futures
from typing import Dict, Any, List, Optional
import httpx
from app.core.logging_config import logger
from app.network.ssrf import validate_url_for_ssrf


# SENSITIVE FILE & PATH SIGNATURES
SENSITIVE_PATHS = [
    {"path": "/.git/HEAD", "sig": "ref: refs/", "risk": "CRITICAL", "title": "Exposed .git Repository", "category": "Code Exposure"},
    {"path": "/.env", "sig": "DB_", "risk": "CRITICAL", "title": "Exposed .env Configuration File", "category": "Credentials Leak"},
    {"path": "/.aws/credentials", "sig": "aws_access_key_id", "risk": "CRITICAL", "title": "Exposed AWS Credentials File", "category": "Cloud Credentials"},
    {"path": "/backup.zip", "sig": "PK\x03\x04", "risk": "HIGH", "title": "Exposed Backup Archive (zip)", "category": "Backup Exposure"},
    {"path": "/backup.sql", "sig": "-- MySQL dump", "risk": "HIGH", "title": "Exposed Database Dump (.sql)", "category": "Database Dump"},
    {"path": "/wp-config.php.bak", "sig": "DB_PASSWORD", "risk": "CRITICAL", "title": "Exposed WordPress Config Backup", "category": "Credentials Leak"},
    {"path": "/phpinfo.php", "sig": "<title>phpinfo()", "risk": "MEDIUM", "title": "Exposed PHPInfo Diagnostic Page", "category": "Information Disclosure"},
    {"path": "/server-status", "sig": "Apache Server Status", "risk": "MEDIUM", "title": "Exposed Apache server-status Page", "category": "Information Disclosure"},
    {"path": "/.dockerenv", "sig": "", "risk": "LOW", "title": "Docker Container Artifact (.dockerenv)", "category": "Container Leak"}
]

# API & DOCUMENTATION PROBE PATHS
API_PROBE_PATHS = [
    {"path": "/openapi.json", "type": "OpenAPI Specification", "match": "openapi"},
    {"path": "/swagger.json", "type": "Swagger Specification", "match": "swagger"},
    {"path": "/v2/swagger.json", "type": "Swagger v2 Specification", "match": "swagger"},
    {"path": "/swagger/index.html", "type": "Swagger UI", "match": "swagger-ui"},
    {"path": "/swagger-ui.html", "type": "Swagger UI", "match": "swagger-ui"},
    {"path": "/docs", "type": "API Documentation", "match": "swagger-ui|redoc"},
    {"path": "/graphql", "type": "GraphQL Endpoint", "match": "GraphQL|schema"},
    {"path": "/graphiql", "type": "GraphiQL Interactive IDE", "match": "graphiql"},
    {"path": "/api/v1", "type": "REST API v1 Root", "match": ""},
    {"path": "/api", "type": "API Root Endpoint", "match": ""}
]

# KNOWN WAF SIGNATURES
WAF_HEADER_SIGNATURES = [
    {"header": "cf-ray", "waf": "Cloudflare WAF / CDN"},
    {"header": "server", "contains": "cloudflare", "waf": "Cloudflare WAF"},
    {"header": "x-amz-cf-id", "waf": "AWS CloudFront WAF"},
    {"header": "x-sucuri-id", "waf": "Sucuri CloudProxy WAF"},
    {"header": "x-akamai-transformed", "waf": "Akamai Kona WAF"},
    {"header": "x-iinfo", "waf": "Imperva / Incapsula WAF"},
    {"header": "x-cdn", "contains": "imperva", "waf": "Imperva WAF"},
    {"header": "x-powered-by", "contains": "f5", "waf": "F5 BIG-IP ASM"},
    {"header": "server", "contains": "barracuda", "waf": "Barracuda Web Application Firewall"},
    {"header": "server", "contains": "fortiweb", "waf": "Fortinet FortiWeb WAF"},
    {"header": "server", "contains": "mod_security", "waf": "ModSecurity WAF"}
]


class ActiveSecurityProber:
    """
    Executes authorized active security probing across targets.
    Strictly verifies SSRF safety before initiating HTTP/TLS/SMTP connections.
    """

    @classmethod
    def probe_all(cls, target_host: str, mx_hosts: Optional[List[str]] = None, authorized: bool = False) -> Dict[str, Any]:
        clean_host = target_host.strip().lower().rstrip("/")
        if "://" in clean_host:
            clean_host = clean_host.split("://", 1)[1].split("/", 1)[0]
        clean_host = clean_host.split(":", 1)[0]

        result: Dict[str, Any] = {
            "target": clean_host,
            "authorized": authorized,
            "executed": False,
            "message": "Active security probing requires explicit operator authorization.",
            "sensitive_files": {"tested": 0, "exposed": []},
            "waf_detection": {"detected": False, "waf_name": None, "blocked_test": False},
            "cors_and_methods": {"tested": False, "dangerous_methods": [], "cors_misconfigured": False, "cors_details": None},
            "tls_cryptography": {"tested": False, "protocols": {}, "deprecated_protocols_found": [], "weak_ciphers": []},
            "api_endpoints": {"tested": 0, "discovered": []},
            "smtp_relay_starttls": {"tested": False, "mx_host": None, "starttls_supported": False, "open_relay": False, "details": None},
            "risk_flags": []
        }

        if not authorized:
            return result

        # Anti-SSRF check
        is_safe, ssrf_reason, resolved_ips = validate_url_for_ssrf(f"http://{clean_host}")
        if not is_safe:
            result["message"] = f"Probing blocked by security policy: {ssrf_reason}"
            return result

        result["executed"] = True
        result["message"] = "Active security probing completed successfully."

        # Fast pre-flight check to test if web server is responsive
        base_https = f"https://{clean_host}"
        base_http = f"http://{clean_host}"
        working_base = None

        try:
            with httpx.Client(timeout=1.0, follow_redirects=True, headers={"User-Agent": "FileSanitizer-Auditor/1.0"}) as client:
                try:
                    resp = client.get(base_https)
                    working_base = base_https
                except Exception:
                    try:
                        resp = client.get(base_http)
                        working_base = base_http
                    except Exception:
                        working_base = None
        except Exception:
            working_base = None

        if working_base:
            # 1. Sensitive File & Directory Exposure Prober
            cls._probe_sensitive_files(working_base, result)

            # 2. WAF & Reverse Proxy Detection
            cls._probe_waf(working_base, result)

            # 3. CORS & HTTP Methods Misconfiguration
            cls._probe_cors_and_methods(working_base, clean_host, result)

            # 4. API Endpoint Discovery
            cls._probe_api_endpoints(working_base, result)

        # 5. TLS Cryptographic Weakness Audit
        cls._probe_tls_weaknesses(clean_host, result)

        # 6. SMTP Relay & STARTTLS
        if mx_hosts:
            cls._probe_smtp(mx_hosts, clean_host, result)

        return result

    # -------------------------------------------------------------------------
    # SENSITIVE FILES (CONCURRENT)
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_sensitive_files(cls, base_url: str, result: Dict[str, Any]) -> None:
        exposed = []
        tested_count = 0

        def _check_path(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            target_url = f"{base_url}{item['path']}"
            try:
                with httpx.Client(timeout=1.2, follow_redirects=False, headers={"User-Agent": "FileSanitizer-Auditor/1.0"}) as client:
                    resp = client.get(target_url)
                if resp.status_code == 200:
                    content_text = resp.text[:1000]
                    sig = item["sig"]
                    is_match = False
                    if not sig:
                        is_match = len(resp.content) > 0 and not ("<html" in content_text.lower() and "404" in content_text)
                    elif sig in content_text or (isinstance(sig, str) and sig.encode() in resp.content[:1000]):
                        is_match = True

                    if is_match:
                        return {
                            "path": item["path"],
                            "title": item["title"],
                            "category": item["category"],
                            "risk": item["risk"],
                            "status_code": resp.status_code,
                            "content_preview": content_text[:120].strip()
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futs = [executor.submit(_check_path, it) for it in SENSITIVE_PATHS]
            for f in concurrent.futures.as_completed(futs):
                tested_count += 1
                match_info = f.result()
                if match_info:
                    exposed.append(match_info)
                    result["risk_flags"].append({
                        "id": f"EXPOSED_{match_info['category'].upper().replace(' ', '_')}",
                        "severity": match_info["risk"],
                        "title": match_info["title"],
                        "description": f"Found publicly accessible sensitive file at {match_info['path']} (HTTP 200). Signature match verified."
                    })

        result["sensitive_files"]["tested"] = tested_count
        result["sensitive_files"]["exposed"] = exposed

    # -------------------------------------------------------------------------
    # WAF DETECTION & ACTIVE EVASION CHECK
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_waf(cls, base_url: str, result: Dict[str, Any]) -> None:
        try:
            with httpx.Client(timeout=1.5, follow_redirects=True, headers={"User-Agent": "FileSanitizer-Auditor/1.0"}) as client:
                norm_resp = client.get(base_url)
                headers_lower = {k.lower(): v.lower() for k, v in norm_resp.headers.items()}
                waf_found = None

                for sig in WAF_HEADER_SIGNATURES:
                    hname = sig["header"]
                    if hname in headers_lower:
                        if "contains" in sig:
                            if sig["contains"] in headers_lower[hname]:
                                waf_found = sig["waf"]
                                break
                        else:
                            waf_found = sig["waf"]
                            break

                # Send benign payload query to check if active blocking engages
                blocked = False
                try:
                    test_payload_url = f"{base_url}/?id=1' AND 1=1--"
                    test_resp = client.get(test_payload_url)
                    if test_resp.status_code in (403, 406, 429, 501):
                        blocked = True
                        if not waf_found:
                            waf_found = "Generic Active Web Application Firewall (WAF)"
                except Exception:
                    pass

                if waf_found:
                    result["waf_detection"]["detected"] = True
                    result["waf_detection"]["waf_name"] = waf_found
                    result["waf_detection"]["blocked_test"] = blocked

        except Exception as e:
            logger.debug(f"WAF probe note: {e}")

    # -------------------------------------------------------------------------
    # CORS & HTTP METHODS MISCONFIGURATION
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_cors_and_methods(cls, base_url: str, host: str, result: Dict[str, Any]) -> None:
        try:
            with httpx.Client(timeout=1.5, follow_redirects=False, headers={"User-Agent": "FileSanitizer-Auditor/1.0"}) as client:
                opt_resp = client.options(base_url)
                allow = opt_resp.headers.get("allow") or opt_resp.headers.get("access-control-allow-methods") or ""
                methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
                dangerous = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "CONNECT")]

                # Test CORS with attacker origin
                attacker_origin = "https://evil-attacker.com"
                cors_resp = client.get(base_url, headers={"Origin": attacker_origin})
                acao = cors_resp.headers.get("access-control-allow-origin", "")
                acac = cors_resp.headers.get("access-control-allow-credentials", "").lower()

                cors_misconfigured = False
                cors_detail = None

                if acao == "*":
                    cors_detail = "Wildcard Access-Control-Allow-Origin: * allowed"
                elif attacker_origin in acao:
                    if acac == "true":
                        cors_misconfigured = True
                        cors_detail = "CRITICAL: Reflected Origin with Access-Control-Allow-Credentials: true"
                        result["risk_flags"].append({
                            "id": "CORS_EXPLOITABLE_CREDENTIAL_LEAK",
                            "severity": "CRITICAL",
                            "title": "Exploitable CORS Misconfiguration with Credentials",
                            "description": "Server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true. Allows attackers to steal authenticated session data cross-origin."
                        })
                    else:
                        cors_detail = "Reflected Origin accepted"

                if dangerous:
                    result["risk_flags"].append({
                        "id": "DANGEROUS_HTTP_METHODS_ENABLED",
                        "severity": "LOW",
                        "title": "Dangerous HTTP Methods Allowed",
                        "description": f"Server permits methods: {', '.join(dangerous)}"
                    })

                result["cors_and_methods"] = {
                    "tested": True,
                    "methods_allowed": methods,
                    "dangerous_methods": dangerous,
                    "cors_misconfigured": cors_misconfigured,
                    "cors_origin_header": acao or None,
                    "cors_credentials_header": acac or None,
                    "cors_details": cors_detail
                }
        except Exception as e:
            logger.debug(f"CORS/Methods probe note: {e}")

    # -------------------------------------------------------------------------
    # TLS CRYPTOGRAPHIC WEAKNESS AUDIT
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_tls_weaknesses(cls, host: str, result: Dict[str, Any]) -> None:
        try:
            # First fast check: is port 443 even accepting TCP connections?
            try:
                with socket.create_connection((host, 443), timeout=0.8) as test_sock:
                    pass
            except Exception:
                # Port 443 not open, skip
                return

            protocols_supported = {}
            deprecated = []

            # Check TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
            protocol_checks = [
                ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None), True),
                ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), True),
                ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None), False),
                ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None), False),
            ]

            for name, ver_const, is_dep in protocol_checks:
                if ver_const is None:
                    continue
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = ver_const
                    ctx.maximum_version = ver_const
                    with socket.create_connection((host, 443), timeout=1.0) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                            protocols_supported[name] = True
                            if is_dep:
                                deprecated.append(name)
                except Exception:
                    protocols_supported[name] = False

            if deprecated:
                result["risk_flags"].append({
                    "id": "DEPRECATED_TLS_PROTOCOLS",
                    "severity": "MEDIUM",
                    "title": "Deprecated TLS Protocols Supported",
                    "description": f"Target server supports deprecated protocols ({', '.join(deprecated)}). Vulnerable to downgrade attacks (POODLE, BEAST)."
                })

            result["tls_cryptography"] = {
                "tested": True,
                "protocols": protocols_supported,
                "deprecated_protocols_found": deprecated,
                "weak_ciphers": []
            }
        except Exception as e:
            logger.debug(f"TLS weakness probe note for {host}: {e}")

    # -------------------------------------------------------------------------
    # REST, OPENAPI & GRAPHQL API ENDPOINT DISCOVERY (CONCURRENT)
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_api_endpoints(cls, base_url: str, result: Dict[str, Any]) -> None:
        discovered = []
        tested_count = 0

        def _check_api(api_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            target_url = f"{base_url}{api_item['path']}"
            try:
                with httpx.Client(timeout=1.2, follow_redirects=True, headers={"User-Agent": "FileSanitizer-Auditor/1.0"}) as client:
                    resp = client.get(target_url)
                if resp.status_code in (200, 204):
                    match_pattern = api_item["match"]
                    is_match = False
                    if not match_pattern:
                        is_match = True
                    elif re.search(match_pattern, resp.text, re.IGNORECASE):
                        is_match = True

                    if is_match:
                        return {
                            "path": api_item["path"],
                            "type": api_item["type"],
                            "status_code": resp.status_code,
                            "content_type": resp.headers.get("content-type", "")
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futs = [executor.submit(_check_api, it) for it in API_PROBE_PATHS]
            for f in concurrent.futures.as_completed(futs):
                tested_count += 1
                api_match = f.result()
                if api_match:
                    discovered.append(api_match)
                    result["risk_flags"].append({
                        "id": "EXPOSED_API_DOCUMENTATION",
                        "severity": "LOW",
                        "title": f"Discovered {api_match['type']}",
                        "description": f"Publicly accessible API documentation or schema located at {api_match['path']}"
                    })

        result["api_endpoints"]["tested"] = tested_count
        result["api_endpoints"]["discovered"] = discovered

    # -------------------------------------------------------------------------
    # SMTP OPEN RELAY & STARTTLS VERIFICATION
    # -------------------------------------------------------------------------
    @classmethod
    def _probe_smtp(cls, mx_hosts: List[str], domain: str, result: Dict[str, Any]) -> None:
        target_mx = None
        for m in mx_hosts:
            host = m.get("host") if isinstance(m, dict) else str(m)
            if host:
                target_mx = host.strip().rstrip(".")
                break

        if not target_mx:
            return

        is_safe, _, resolved = validate_url_for_ssrf(f"http://{target_mx}")
        if not is_safe or not resolved:
            return

        mx_ip = resolved[0]
        smtp_info: Dict[str, Any] = {
            "tested": True,
            "mx_host": target_mx,
            "mx_ip": mx_ip,
            "banner": None,
            "starttls_supported": False,
            "open_relay": False,
            "details": None
        }

        try:
            with socket.create_connection((mx_ip, 25), timeout=1.5) as sock:
                sock.settimeout(1.5)
                banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
                smtp_info["banner"] = banner.split("\r\n")[0][:100]

                sock.sendall(b"EHLO filesanitizer.test\r\n")
                ehlo_resp = sock.recv(1024).decode("utf-8", errors="ignore")
                if "STARTTLS" in ehlo_resp.upper():
                    smtp_info["starttls_supported"] = True

                sock.sendall(b"MAIL FROM:<test-audit@filesanitizer.test>\r\n")
                mail_resp = sock.recv(512).decode("utf-8", errors="ignore")

                sock.sendall(b"RCPT TO:<relay-check-nonexistent@example.org>\r\n")
                rcpt_resp = sock.recv(512).decode("utf-8", errors="ignore")

                sock.sendall(b"QUIT\r\n")

                if rcpt_resp.startswith("250") or rcpt_resp.startswith("251"):
                    smtp_info["open_relay"] = True
                    result["risk_flags"].append({
                        "id": "SMTP_OPEN_RELAY_VULNERABLE",
                        "severity": "CRITICAL",
                        "title": "SMTP Mail Server Open Relay Vulnerability",
                        "description": f"Mail server {target_mx} accepted relaying mail to external recipient without authentication. Vulnerable to spam relaying and phishing abuse."
                    })
                else:
                    smtp_info["details"] = "Relay rejected (Secure)"

            if not smtp_info["starttls_supported"]:
                result["risk_flags"].append({
                    "id": "SMTP_NO_STARTTLS",
                    "severity": "MEDIUM",
                    "title": "SMTP Mail Server Missing STARTTLS",
                    "description": f"Mail server {target_mx} does not advertise STARTTLS. Email in transit can be intercepted or read in cleartext."
                })

        except Exception as e:
            logger.debug(f"SMTP probe note for {target_mx}: {e}")
            smtp_info["details"] = f"Port 25 unreachable ({type(e).__name__})"

        result["smtp_relay_starttls"] = smtp_info
