import re
import time
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, UploadFile, File, status, Response, Query
from pydantic import BaseModel, Field

from app.config import settings as app_settings
from app.core.settings_store import (
    settings_store,
    verify_admin_login,
    create_admin_token,
    verify_admin_token
)
from app.core.clamav_manager import clamav_manager
from app.core.yara_manager import yara_manager
from app.core.logging_config import logger, audit_log_manager

router = APIRouter(prefix="/settings", tags=["Settings & Administration"])

# Auth dependency
def require_admin(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = authorization[7:].strip()
    payload = verify_admin_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired admin session token. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return payload

# Request models
class LoginRequest(BaseModel):
    username: str
    password: str

class SettingsUpdateRequest(BaseModel):
    global_checks: Optional[Dict[str, bool]] = None
    format_checks: Optional[Dict[str, Dict[str, bool]]] = None
    api_keys: Optional[Dict[str, str]] = None
    evtx_timeline_event_ids: Optional[List[int]] = None
    evtx_severity_rules: Optional[Dict[str, str]] = None
    time_display: Optional[Dict[str, Any]] = None
    ui_preferences: Optional[Dict[str, Any]] = None
    cache_settings: Optional[Dict[str, Any]] = None

class YaraRuleCreateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    severity: str = "HIGH"
    target_format: str = "ALL"
    rule_text: str

class YaraRuleUpdateRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    severity: str = "HIGH"
    target_format: str = "ALL"
    rule_text: str

class YaraValidateRequest(BaseModel):
    rule_text: str

class YaraRuleToggleRequest(BaseModel):
    enabled: bool

class ExternalPolicyUpdateRequest(BaseModel):
    allow_all_external: Optional[bool] = None
    allow_http_status_and_redirects: Optional[bool] = None
    allow_screenshots: Optional[bool] = None
    allow_tls_inspection: Optional[bool] = None
    allow_threat_intel_lookups: Optional[bool] = None
    allow_geolocation_lookups: Optional[bool] = None
    allow_clamav_official_updates: Optional[bool] = None

# 1. Admin Authentication
@router.post("/login")
def login(req: LoginRequest):
    if not verify_admin_login(req.username, req.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid administrator username or password."
        )
    token = create_admin_token(req.username)
    return {
        "success": True,
        "token": token,
        "username": req.username,
        "message": "Authentication successful"
    }

@router.get("/verify")
def verify_session(admin=Depends(require_admin)):
    return {"valid": True, "username": admin.get("sub", "admin")}

@router.get("/time-display")
def get_time_display_settings():
    """Public endpoint to get server-configured time display preferences."""
    return {
        "success": True,
        "time_display": settings_store.get_time_display()
    }

@router.put("/time-display")
def update_time_display_settings(config: Dict[str, Any], admin=Depends(require_admin)):
    """Admin endpoint to update time display and timezone preferences."""
    settings_store.set_time_display(config)
    return {
        "success": True,
        "time_display": settings_store.get_time_display()
    }

@router.get("/ui-preferences")
def get_ui_preferences_settings():
    """Public endpoint to get server-configured UI display preferences."""
    return {
        "success": True,
        "ui_preferences": settings_store.get_ui_preferences()
    }

@router.put("/ui-preferences")
def update_ui_preferences_settings(config: Dict[str, Any], admin=Depends(require_admin)):
    """Admin endpoint to update UI display preferences."""
    settings_store.set_ui_preferences(config)
    return {
        "success": True,
        "ui_preferences": settings_store.get_ui_preferences()
    }

_UPDATE_CHECK_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}
_UPDATE_CACHE_TTL = 3600  # 1 hour

def _parse_semver(v: str) -> tuple:
    clean = re.sub(r'^[vV]', '', (v or '').strip())
    parts = []
    for p in clean.split('.'):
        m = re.match(r'^\d+', p)
        parts.append(int(m.group(0)) if m else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

@router.get("/check-update")
def check_for_updates(force: bool = False, simulate_version: Optional[str] = Query(None)):
    """
    Checks GitHub for new releases or updates to FileSanitizer.
    Supports GitHub Releases API (/releases/latest) with fallback to main branch version.ts.
    Cached for 1 hour unless force=True.
    """
    global _UPDATE_CHECK_CACHE

    current_ver = app_settings.APP_VERSION
    now = time.time()

    # Testing hook: allow simulating a release version
    if simulate_version:
        sim_v = simulate_version.lstrip("v").strip()
        sim_has_update = _parse_semver(sim_v) > _parse_semver(current_ver)
        return {
            "success": True,
            "has_update": sim_has_update,
            "current_version": current_ver,
            "latest_version": sim_v,
            "release_name": f"FileSanitizer v{sim_v} - Security & Analysis Enhancements",
            "release_notes": f"• Enhanced Java Bytecode Analysis\n• Automated APK Manifest & DEX Inspection\n• Upgraded YARA Engine v{sim_v}",
            "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "html_url": f"https://github.com/jozeta/FileSanitizer/releases/tag/v{sim_v}",
            "source": "simulated",
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    # Check external connection policy
    ext_conn = settings_store.get_external_policy()
    if not ext_conn.get("allow_all_external", True):
        return {
            "success": True,
            "has_update": False,
            "current_version": current_ver,
            "external_blocked": True,
            "message": "External network requests are disabled in settings.",
        }

    # Return cached data if valid and force is False
    if not force and _UPDATE_CHECK_CACHE.get("data") and (now - _UPDATE_CHECK_CACHE.get("timestamp", 0) < _UPDATE_CACHE_TTL):
        return _UPDATE_CHECK_CACHE["data"]

    headers = {
        "User-Agent": f"FileSanitizer-Update-Check/{current_ver}",
        "Accept": "application/vnd.github.v3+json",
    }

    latest_version = None
    release_name = None
    release_notes = None
    published_at = None
    html_url = "https://github.com/jozeta/FileSanitizer"
    source = "unknown"

    try:
        import httpx
        with httpx.Client(timeout=6.0, follow_redirects=True, headers=headers) as client:
            # 1. Attempt GitHub Releases API
            try:
                rel_resp = client.get("https://api.github.com/repos/jozeta/FileSanitizer/releases/latest")
                if rel_resp.status_code == 200:
                    data = rel_resp.json()
                    tag = data.get("tag_name", "").strip()
                    if tag:
                        latest_version = tag.lstrip("v")
                        release_name = data.get("name") or f"FileSanitizer v{latest_version}"
                        release_notes = data.get("body") or ""
                        published_at = data.get("published_at")
                        html_url = data.get("html_url") or f"https://github.com/jozeta/FileSanitizer/releases/tag/{tag}"
                        source = "github_release"
            except Exception as e_rel:
                logger.debug(f"GitHub Releases check failed: {e_rel}")

            # 2. Fallback to raw version.ts on main branch
            if not latest_version:
                raw_resp = client.get("https://raw.githubusercontent.com/jozeta/FileSanitizer/main/frontend/src/version.ts")
                if raw_resp.status_code == 200:
                    content = raw_resp.text
                    v_match = re.search(r"APP_VERSION\s*=\s*['\"]([^'\"]+)['\"]", content)
                    name_match = re.search(r"APP_RELEASE_NAME\s*=\s*['\"]([^'\"]+)['\"]", content)
                    date_match = re.search(r"APP_BUILD_DATE\s*=\s*['\"]([^'\"]+)['\"]", content)
                    if v_match:
                        latest_version = v_match.group(1).lstrip("v")
                        release_name = name_match.group(1) if name_match else f"FileSanitizer v{latest_version}"
                        published_at = date_match.group(1) if date_match else None
                        release_notes = f"Release build: {release_name}"
                        html_url = "https://github.com/jozeta/FileSanitizer"
                        source = "github_main_branch"

        if not latest_version:
            return {
                "success": False,
                "has_update": False,
                "current_version": current_ver,
                "error": "Could not determine latest version from GitHub.",
            }

        has_update = _parse_semver(latest_version) > _parse_semver(current_ver)

        result = {
            "success": True,
            "has_update": has_update,
            "current_version": current_ver,
            "latest_version": latest_version,
            "release_name": release_name,
            "release_notes": release_notes,
            "published_at": published_at,
            "html_url": html_url,
            "source": source,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        _UPDATE_CHECK_CACHE["timestamp"] = now
        _UPDATE_CHECK_CACHE["data"] = result
        return result

    except Exception as e:
        logger.warning(f"Error checking GitHub for updates: {e}")
        return {
            "success": False,
            "has_update": False,
            "current_version": current_ver,
            "error": str(e),
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

# 2. General Settings
@router.get("")
def get_settings(admin=Depends(require_admin)):
    return {
        "success": True,
        "settings": settings_store.get_all(mask_keys=True)
    }

@router.put("")
def update_settings(req: SettingsUpdateRequest, admin=Depends(require_admin)):
    payload = req.model_dump(exclude_unset=True)
    updated = settings_store.update(payload)
    return {
        "success": True,
        "message": "Settings updated successfully.",
        "settings": updated
    }

# 3. ClamAV Engine & Definitions Management
@router.get("/clamav")
def get_clamav_status(admin=Depends(require_admin)):
    info = clamav_manager.get_info()
    return {"success": True, "clamav": info}

@router.get("/clamav/check-updates")
def check_clamav_updates(force: bool = False, simulate_newer: bool = False, admin=Depends(require_admin)):
    """Check official ClamAV mirror in background to verify if newer definitions exist."""
    res = clamav_manager.check_for_updates(force=force)
    if simulate_newer:
        res = dict(res)
        res["newer_available"] = True
        res["remote_version"] = (res.get("local_version") or 28134) + 1
        res["message"] = f"Newer definition files exist! Version {res['remote_version']} is available from official ClamAV mirror (Current: {res.get('local_version')})."
    return {"success": True, "update_check": res}

@router.post("/clamav/update")
def update_clamav_mirror(admin=Depends(require_admin)):
    res = clamav_manager.update_from_mirror()
    return res

@router.get("/clamav/update-progress")
def get_clamav_update_progress(admin=Depends(require_admin)):
    progress = clamav_manager.get_download_progress()
    return {"success": True, "progress": progress}

@router.post("/clamav/upload-definitions")
async def upload_clamav_definitions(
    file: UploadFile = File(...),
    admin=Depends(require_admin)
):
    try:
        content = await file.read()
        res = clamav_manager.install_definition_file(file.filename, content)
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to upload definition file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process definition file: {e}")

class CommunitySignatureInstallRequest(BaseModel):
    pack: str

@router.post("/clamav/community-signatures")
def install_clamav_community_signatures(req: CommunitySignatureInstallRequest, admin=Depends(require_admin)):
    res = clamav_manager.install_community_pack(req.pack)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to install community signatures"))
    return res

# 4. YARA Rules Management

@router.get("/yara/rules")
def list_yara_rules(admin=Depends(require_admin)):
    rules = yara_manager.list_rules()
    return {"success": True, "rules": rules}

@router.post("/yara/rules")
def add_yara_rule(req: YaraRuleCreateRequest, admin=Depends(require_admin)):
    try:
        record = yara_manager.add_rule(
            name=req.name,
            description=req.description or "",
            severity=req.severity,
            target_format=req.target_format,
            rule_text=req.rule_text
        )
        return {
            "success": True,
            "message": f"YARA rule '{req.name}' successfully compiled and activated.",
            "rule": record
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create YARA rule: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error saving YARA rule: {e}")

@router.delete("/yara/rules/{rule_id}")
def delete_yara_rule(rule_id: str, admin=Depends(require_admin)):
    deleted = yara_manager.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"YARA rule '{rule_id}' not found.")
    return {"success": True, "message": f"Rule {rule_id} deleted."}

@router.put("/yara/rules/{rule_id}/toggle")
def toggle_yara_rule(rule_id: str, req: YaraRuleToggleRequest, admin=Depends(require_admin)):
    updated = yara_manager.toggle_rule(rule_id, req.enabled)
    if not updated:
        raise HTTPException(status_code=404, detail=f"YARA rule '{rule_id}' not found.")
    return {"success": True, "rule": updated}

@router.put("/yara/rules/{rule_id}")
def update_yara_rule(rule_id: str, req: YaraRuleUpdateRequest, admin=Depends(require_admin)):
    try:
        updated = yara_manager.update_rule(
            rule_id=rule_id,
            name=req.name,
            description=req.description or "",
            severity=req.severity,
            target_format=req.target_format,
            rule_text=req.rule_text
        )
        if not updated:
            raise HTTPException(status_code=404, detail=f"YARA rule '{rule_id}' not found.")
        return {
            "success": True,
            "message": f"YARA rule '{req.name}' updated and re-compiled.",
            "rule": updated
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update YARA rule: {e}")
        raise HTTPException(status_code=500, detail=f"Internal error updating YARA rule: {e}")

@router.post("/yara/validate")
def validate_yara_rule(req: YaraValidateRequest, admin=Depends(require_admin)):
    valid, err = yara_manager.validate_rule_syntax(req.rule_text)
    return {"valid": valid, "error": err}

@router.get("/yara/community-packs")
def list_yara_community_packs(admin=Depends(require_admin)):
    packs = yara_manager.get_community_packs()
    return {"success": True, "packs": packs}

@router.post("/yara/community-packs/{pack_id}/import")
def import_yara_community_pack(pack_id: str, admin=Depends(require_admin)):
    res = yara_manager.import_community_pack(pack_id)
    return res

# 5. Warninglist / Watchlist Management
class WarningRuleCreateRequest(BaseModel):
    name: Optional[str] = ""
    pattern: str
    is_regex: bool = False
    severity: str = "medium"  # informational / info, low, medium, high, critical
    description: Optional[str] = ""

class WarningRuleUpdateRequest(BaseModel):
    name: Optional[str] = ""
    pattern: str
    is_regex: bool = False
    severity: str = "medium"
    description: Optional[str] = ""

@router.get("/warninglist")
def list_warning_rules(admin=Depends(require_admin)):
    rules = settings_store.get_warning_rules()
    return {"success": True, "rules": rules}

@router.post("/warninglist")
def add_warning_rule(req: WarningRuleCreateRequest, admin=Depends(require_admin)):
    if not req.pattern or not req.pattern.strip():
        raise HTTPException(status_code=400, detail="Pattern/keyword cannot be empty.")
    # Test regex compilation if is_regex
    if req.is_regex:
        import re
        try:
            re.compile(req.pattern)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regular expression: {e}")

    rule = settings_store.add_warning_rule(
        pattern=req.pattern,
        is_regex=req.is_regex,
        severity=req.severity,
        description=req.description or "",
        name=req.name or ""
    )
    return {
        "success": True,
        "message": f"Warning rule '{rule.get('name')}' added successfully.",
        "rule": rule
    }

@router.put("/warninglist/{rule_id}")
def update_warning_rule(rule_id: str, req: WarningRuleUpdateRequest, admin=Depends(require_admin)):
    if not req.pattern or not req.pattern.strip():
        raise HTTPException(status_code=400, detail="Pattern/keyword cannot be empty.")
    if req.is_regex:
        import re
        try:
            re.compile(req.pattern)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regular expression: {e}")

    updated = settings_store.update_warning_rule(
        rule_id=rule_id,
        pattern=req.pattern,
        is_regex=req.is_regex,
        severity=req.severity,
        description=req.description or "",
        name=req.name or ""
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Warning rule '{rule_id}' not found.")
    return {
        "success": True,
        "message": f"Warning rule '{updated.get('name')}' updated successfully.",
        "rule": updated
    }

@router.delete("/warninglist/{rule_id}")
def delete_warning_rule(rule_id: str, admin=Depends(require_admin)):
    deleted = settings_store.delete_warning_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Warning rule '{rule_id}' not found.")
    return {"success": True, "message": f"Rule {rule_id} removed."}

@router.post("/warninglist/{rule_id}/toggle")
def toggle_warning_rule(rule_id: str, admin=Depends(require_admin)):
    status = settings_store.toggle_warning_rule(rule_id)
    if status is None:
        raise HTTPException(status_code=404, detail=f"Warning rule '{rule_id}' not found.")
    return {"success": True, "enabled": status}

# 6. Granular External Network Policy Controls
@router.get("/external-policy")
def get_external_policy(admin=Depends(require_admin)):
    policy = settings_store.get_external_policy()
    return {"success": True, "policy": policy}

@router.put("/external-policy")
def update_external_policy(req: ExternalPolicyUpdateRequest, admin=Depends(require_admin)):
    updates = req.model_dump(exclude_unset=True)
    updated = settings_store.update_external_policy(updates)
    return {
        "success": True,
        "message": "External network policies updated successfully.",
        "policy": updated
    }

# 7. Aggregated Telemetry & Upload Statistics
@router.get("/statistics")
def get_statistics(admin=Depends(require_admin)):
    stats = settings_store.get_statistics()
    return {"success": True, "statistics": stats}

# 7b. Upload History Log
@router.get("/history")
def get_upload_history(admin=Depends(require_admin)):
    return {
        "success": True,
        "history": settings_store.get_upload_history(),
        "enabled": settings_store.is_history_enabled(),
    }

@router.delete("/history")
def clear_upload_history(admin=Depends(require_admin)):
    settings_store.clear_upload_history()
    return {"success": True}

@router.put("/history/toggle")
def toggle_history(payload: dict, admin=Depends(require_admin)):
    settings_store.toggle_upload_history(bool(payload.get("enabled", True)))
    return {"success": True, "enabled": settings_store.is_history_enabled()}

# 8. API Key Verification Probes
class VerifyKeyRequest(BaseModel):
    service: str  # "virustotal", "urlhaus", "safebrowsing"
    api_key: Optional[str] = None
    key: Optional[str] = None

@router.post("/verify-key")
@router.post("/verify-api-key")
def verify_api_key(req: VerifyKeyRequest, admin=Depends(require_admin)):
    import httpx
    service = req.service.lower().strip()
    raw_key = req.api_key or req.key or ""
    key = raw_key.strip()
    # If the frontend passes a masked placeholder (e.g. "abcd...1234" or "********"), fall back to the real saved key
    if key and ("..." in key or "*" in key):
        key = ""
    if not key:
        if service == "virustotal":
            key = settings_store.get_api_key("virustotal_api_key")

        elif service == "urlhaus":
            key = settings_store.get_api_key("urlhaus_api_key")
        elif service in ["safebrowsing", "safe_browsing"]:
            key = settings_store.get_api_key("safe_browsing_api_key")
        elif service == "abuseipdb":
            key = settings_store.get_api_key("abuseipdb_api_key")
        elif service in ["alienvault", "alienvault_otx"]:
            key = settings_store.get_api_key("alienvault_otx_api_key")
        elif service in ["hybridanalysis", "hybrid_analysis", "falcon"]:
            key = settings_store.get_api_key("hybrid_analysis_api_key")
        elif service in ["mxtoolbox", "mx_toolbox"]:
            key = settings_store.get_api_key("mxtoolbox_api_key")
        elif service in ["ipinfo", "ipinfo_io"]:
            key = settings_store.get_api_key("ipinfo_api_key")
        elif service == "shodan":
            key = settings_store.get_api_key("shodan_api_key")

    if not key and service not in ["circl", "circl_hashlookup", "hashlookup", "rdap", "whois", "iana", "ipinfo", "ipinfo_io"]:
        raise HTTPException(status_code=400, detail="API key is empty or not provided.")

    try:
        if service == "virustotal":
            with httpx.Client(timeout=8.0) as client:
                res = client.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": key})
                if res.status_code == 200:
                    return {"valid": True, "service": "virustotal", "message": "VirusTotal API key verified successfully! Connected and ready."}
                elif res.status_code in [401, 403]:
                    return {"valid": False, "service": "virustotal", "message": "Authentication failed: Invalid VirusTotal API key (HTTP 401/403)."}
                elif res.status_code == 429:
                    return {"valid": True, "service": "virustotal", "message": "Key is valid, but rate limit quota is currently reached (HTTP 429)."}
                else:
                    return {"valid": False, "service": "virustotal", "message": f"VirusTotal returned unexpected status HTTP {res.status_code}."}

        elif service == "urlhaus":
            with httpx.Client(timeout=8.0) as client:
                res = client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": "https://google.com"}, headers={"Auth-Key": key})
                if res.status_code == 200:
                    return {"valid": True, "service": "urlhaus", "message": "Abuse.ch URLhaus Auth-Key verified successfully! Connected and ready."}
                elif res.status_code in [401, 403]:
                    return {"valid": False, "service": "urlhaus", "message": "Authentication failed: Invalid URLhaus Auth-Key (HTTP 401/403)."}
                else:
                    return {"valid": False, "service": "urlhaus", "message": f"URLhaus returned HTTP {res.status_code}."}

        elif service in ["safebrowsing", "safe_browsing"]:
            with httpx.Client(timeout=8.0) as client:
                payload = {
                    "client": {"clientId": "FileSanitizer", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": "http://google.com"}]
                    }
                }
                res = client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=payload)
                if res.status_code == 200:
                    return {"valid": True, "service": "safebrowsing", "message": "Google Safe Browsing API key verified successfully! Connected and ready."}
                elif res.status_code == 400:
                    return {"valid": False, "service": "safebrowsing", "message": "Invalid Google Safe Browsing API key (HTTP 400)."}
                else:
                    return {"valid": False, "service": "safebrowsing", "message": f"Safe Browsing API returned HTTP {res.status_code}."}

        elif service == "abuseipdb":
            from app.analyzers.reputation_client import AbuseIPDBClient
            valid, msg = AbuseIPDBClient.verify_key(key)
            return {"valid": valid, "service": "abuseipdb", "message": msg}

        elif service in ["alienvault", "alienvault_otx"]:
            from app.analyzers.reputation_client import AlienVaultOTXClient
            valid, msg = AlienVaultOTXClient.verify_key(key)
            return {"valid": valid, "service": "alienvault_otx", "message": msg}

        elif service in ["threatfox", "threat_fox"]:
            from app.analyzers.reputation_client import ThreatFoxClient
            valid, msg = ThreatFoxClient.verify_key(key)
            return {"valid": valid, "service": "threatfox", "message": msg}

        elif service in ["urlscan", "urlscan_io"]:
            from app.analyzers.reputation_client import UrlScanClient
            valid, msg = UrlScanClient.verify_key(key)
            return {"valid": valid, "service": "urlscan", "message": msg}

        elif service in ["hybridanalysis", "hybrid_analysis", "falcon"]:
            from app.analyzers.reputation_client import HybridAnalysisClient
            valid, msg = HybridAnalysisClient.verify_key(key)
            return {"valid": valid, "service": "hybrid_analysis", "message": msg}

        elif service in ["mxtoolbox", "mx_toolbox"]:
            from app.analyzers.reputation_client import MXToolboxClient
            valid, msg = MXToolboxClient.verify_key(key)
            return {"valid": valid, "service": "mxtoolbox", "message": msg}

        elif service == "shodan":
            from app.network.shodan_client import ShodanClient
            valid, msg = ShodanClient.verify_key(key)
            return {"valid": valid, "service": "shodan", "message": msg}

        elif service in ["rdap", "whois", "iana"]:
            from app.analyzers.reputation_client import RdapClient
            valid, msg = RdapClient.verify_service()
            return {"valid": valid, "service": "rdap", "message": msg}

        elif service in ["ipinfo", "ipinfo_io"]:
            from app.analyzers.reputation_client import IPinfoClient
            valid, msg = IPinfoClient.verify_key(key)
            return {"valid": valid, "service": "ipinfo", "message": msg}

        elif service in ["circl", "circl_hashlookup", "hashlookup"]:
            from app.analyzers.reputation_client import CirclHashlookupClient
            valid, msg = CirclHashlookupClient.verify_service()
            return {"valid": valid, "service": "circl", "message": msg}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported service: {service}")


    except Exception as e:
        logger.error(f"Error testing API key for {service}: {e}")
        return {"valid": False, "service": service, "message": f"Network error connecting to {service}: {str(e)}"}

# 9. Dangerous URL File Extensions Management
class DangerousExtensionRequest(BaseModel):
    extension: str

@router.get("/dangerous-extensions")
def get_dangerous_extensions(admin=Depends(require_admin)):
    extensions = settings_store.get_dangerous_extensions()
    return {"success": True, "extensions": extensions}

@router.post("/dangerous-extensions")
def add_dangerous_extension(req: DangerousExtensionRequest, admin=Depends(require_admin)):
    if not req.extension or not req.extension.strip():
        raise HTTPException(status_code=400, detail="Extension cannot be empty.")
    updated = settings_store.add_dangerous_extension(req.extension)
    return {"success": True, "message": f"Extension '{req.extension}' added.", "extensions": updated}

@router.delete("/dangerous-extensions/{extension}")
def remove_dangerous_extension(extension: str, admin=Depends(require_admin)):
    updated = settings_store.remove_dangerous_extension(extension)
    return {"success": True, "message": f"Extension '{extension}' removed.", "extensions": updated}


# 10. Custom ImHex-like Search & Hex Highlighting Patterns
class CustomPatternRequest(BaseModel):
    name: str
    pattern: str = ""
    type: str = "string"  # "string", "regex", "hex", "struct_field"
    color: str = "#6366f1"
    description: Optional[str] = ""
    offset: Optional[int] = None
    length: Optional[int] = None
    structure_type: Optional[str] = "header"
    appliesToFormat: Optional[str] = None
    category: Optional[str] = None
    is_builtin: Optional[bool] = False
    is_modified: Optional[bool] = False

@router.get("/custom-patterns")
def get_custom_patterns():
    """Get all custom search and hex patterns (accessible to inspector)."""
    patterns = settings_store.get_custom_hex_patterns()
    return {"success": True, "patterns": patterns}

@router.post("/custom-patterns")
def add_custom_pattern(req: CustomPatternRequest, admin=Depends(require_admin)):
    if req.type != "struct_field" and (not req.pattern or not req.pattern.strip()):
        raise HTTPException(status_code=400, detail="Pattern value cannot be empty.")
    item = settings_store.add_custom_hex_pattern(
        name=req.name,
        pattern=req.pattern or "",
        p_type=req.type,
        color=req.color,
        description=req.description or "",
        offset=req.offset,
        length=req.length,
        structure_type=req.structure_type or "header",
        applies_to_format=req.appliesToFormat,
        category=req.category
    )
    return {"success": True, "message": f"Pattern '{req.name}' added successfully.", "pattern": item}

@router.put("/custom-patterns/{pattern_id}")
def update_custom_pattern(pattern_id: str, req: CustomPatternRequest, admin=Depends(require_admin)):
    updated = settings_store.update_custom_hex_pattern(
        pat_id=pattern_id,
        name=req.name,
        pattern=req.pattern or "",
        p_type=req.type,
        color=req.color,
        description=req.description or "",
        offset=req.offset,
        length=req.length,
        structure_type=req.structure_type or "header",
        applies_to_format=req.appliesToFormat,
        category=req.category,
        is_builtin=bool(req.is_builtin)
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Pattern not found.")
    return {"success": True, "message": "Pattern updated successfully.", "pattern": updated}

@router.post("/custom-patterns/{pattern_id}/reset")
def reset_custom_pattern(pattern_id: str, admin=Depends(require_admin)):
    """Reset a modified built-in pattern back to its factory default."""
    ok = settings_store.reset_custom_hex_pattern(pattern_id)
    return {"success": True, "message": "Pattern reset to default."}

@router.delete("/custom-patterns/{pattern_id}")
def delete_custom_pattern(pattern_id: str, admin=Depends(require_admin)):
    ok = settings_store.delete_custom_hex_pattern(pattern_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Pattern not found.")
    return {"success": True, "message": "Pattern deleted successfully."}

@router.post("/custom-patterns/{pattern_id}/toggle")
def toggle_custom_pattern(pattern_id: str, admin=Depends(require_admin)):
    enabled = settings_store.toggle_custom_hex_pattern(pattern_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="Pattern not found.")
    return {"success": True, "enabled": enabled}

# 11. Supported File Formats Management
class FileFormatRequest(BaseModel):
    id: Optional[str] = None
    name: str
    default_extension: Optional[str] = None
    magic_bytes: Optional[str] = ""
    extensions: Optional[List[str]] = None
    magic_signatures: Optional[List[str]] = None
    description: Optional[str] = ""

@router.get("/file-formats")
def get_file_formats():
    """Get all supported file formats."""
    formats = settings_store.get_file_formats()
    return {"success": True, "formats": formats}

@router.post("/file-formats")
def add_file_format(req: FileFormatRequest, admin=Depends(require_admin)):
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Format name is required.")
    try:
        new_fmt = settings_store.add_file_format(
            fmt_id=req.id or "",
            name=req.name,
            default_extension=req.default_extension or "",
            magic_bytes=req.magic_bytes or "",
            extensions=req.extensions,
            magic_signatures=req.magic_signatures,
            description=req.description or ""
        )
        return {"success": True, "message": f"File format '{req.name}' created.", "format": new_fmt}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/file-formats/{format_id}")
def update_file_format(format_id: str, req: FileFormatRequest, admin=Depends(require_admin)):
    updated = settings_store.update_file_format(
        fmt_id=format_id,
        name=req.name,
        default_extension=req.default_extension or "",
        magic_bytes=req.magic_bytes or "",
        extensions=req.extensions,
        magic_signatures=req.magic_signatures,
        description=req.description or ""
    )
    if not updated:
        raise HTTPException(status_code=404, detail="File format not found.")
    return {"success": True, "message": f"File format '{req.name}' updated.", "format": updated}

@router.delete("/file-formats/{format_id}")
def delete_file_format(format_id: str, admin=Depends(require_admin)):
    try:
        ok = settings_store.delete_file_format(format_id)
        if not ok:
            raise HTTPException(status_code=404, detail="File format not found.")
        return {"success": True, "message": "File format deleted."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/file-formats/{format_id}/toggle")
def toggle_file_format(format_id: str, admin=Depends(require_admin)):
    enabled = settings_store.toggle_file_format(format_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="File format not found.")
    return {"success": True, "enabled": enabled}

# 12. Audit & System Debug Logs Management
class LogLevelUpdateRequest(BaseModel):
    level: str

@router.get("/logs")
def get_audit_logs(
    limit: int = Query(default=300, ge=1, le=1000),
    level: Optional[str] = Query(default="ALL"),
    search: Optional[str] = Query(default=None),
    offset: int = Query(default=0, ge=0),
    admin=Depends(require_admin)
):
    """Retrieve detailed real-time application audit and debug logs."""
    data = audit_log_manager.get_logs(limit=limit, level=level, search=search, offset=offset)
    return {"success": True, **data}

@router.delete("/logs")
def clear_audit_logs(admin=Depends(require_admin)):
    """Clear the active audit log ring buffer."""
    audit_log_manager.clear()
    logger.info("Admin cleared application audit log buffer")
    return {"success": True, "message": "Audit logs cleared successfully."}

@router.post("/logs/level")
def set_log_level(req: LogLevelUpdateRequest, admin=Depends(require_admin)):
    """Dynamically set the system logging level (DEBUG, INFO, WARNING, ERROR)."""
    valid = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    target = req.level.strip().upper()
    if target not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid log level. Choose from: {', '.join(valid)}")
    new_lvl = audit_log_manager.set_level(target)
    logger.info(f"Admin updated system logging level to {new_lvl}")
    return {"success": True, "message": f"Log level updated to {new_lvl}", "level": new_lvl}

@router.get("/logs/export")
def export_audit_logs(
    format: str = "text",
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    """Export application audit and debug logs as plain text or JSON."""
    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization[7:].strip()
    elif token:
        auth_token = token.strip()
    if not auth_token or not verify_admin_token(auth_token):
        raise HTTPException(status_code=401, detail="Admin authentication required.")

    from datetime import datetime, timezone
    now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if format.lower() == "json":
        import json
        logs_data = audit_log_manager.get_logs(limit=5000)
        content = json.dumps(logs_data, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="filesanitizer_audit_logs_{now_str}.json"'}
        )
    else:
        text_data = audit_log_manager.export_text()
        return Response(
            content=text_data,
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="filesanitizer_audit_logs_{now_str}.log"'}
        )

# --- External API & Threat Intelligence Cache Management ---
@router.get("/cache")
def get_cache_stats(admin=Depends(require_admin)):
    """Retrieve external API cache statistics, policy, and Redis hit/miss rates."""
    from app.core.external_cache import external_api_cache
    from app.core.redis_cache import redis_cache
    stats = external_api_cache.get_stats()
    redis_stats = redis_cache.get_stats()
    stats["redis"] = redis_stats
    stats["connected"] = redis_stats.get("connected", False)
    stats["used_memory_human"] = redis_stats.get("used_memory_human", "0B")
    return {"success": True, "stats": stats}

@router.get("/cache/settings")
def get_cache_settings():
    """Retrieve external API cache lifetime and mode policies."""
    return {"success": True, "cache_settings": settings_store.get_cache_settings()}

@router.put("/cache/settings")
def update_cache_settings(config: Dict[str, Any], admin=Depends(require_admin)):
    """Update external API cache lifetime (hours/days) and policy (always fetch vs use cache)."""
    settings_store.set_cache_settings(config)
    return {"success": True, "cache_settings": settings_store.get_cache_settings()}

@router.post("/cache/clear")
def clear_intelligence_cache(
    namespace: Optional[str] = Query(None),
    admin=Depends(require_admin)
):
    """Flush cached threat intelligence records from persistent SQLite and Redis."""
    from app.core.external_cache import external_api_cache
    deleted = external_api_cache.clear(service=namespace)
    logger.info("Admin flushed external API cache (service=%s, keys_deleted=%d)", namespace, deleted)
    return {"success": True, "keys_deleted": deleted, "namespace": namespace or "all"}

# --- Archive Password Pipeline Dictionary Management ---
class ArchivePasswordRequest(BaseModel):
    password: Optional[str] = None
    passwords: Optional[List[str]] = None

@router.get("/archive-passwords")
def get_archive_passwords():
    """Retrieve list of default/campaign passwords in the auto-unlocking pipeline."""
    return {"success": True, "passwords": settings_store.get_archive_passwords()}

@router.post("/archive-passwords")
def save_archive_passwords(
    req: ArchivePasswordRequest,
    admin=Depends(require_admin)
):
    """Add or update passwords in the auto-unlocking pipeline."""
    if req.passwords is not None:
        updated = settings_store.set_archive_passwords(req.passwords)
        return {"success": True, "passwords": updated}
    elif req.password:
        updated = settings_store.add_archive_password(req.password)
        return {"success": True, "passwords": updated}
    else:
        raise HTTPException(status_code=400, detail="Must provide 'password' or 'passwords'")

@router.delete("/archive-passwords/{password}")
def delete_archive_password(
    password: str,
    admin=Depends(require_admin)
):
    """Remove a password from the auto-unlocking pipeline."""
    updated = settings_store.delete_archive_password(password)
    return {"success": True, "passwords": updated}

# --- Format-Specific CDR & Sanitization Policies ---
class CdrPolicyUpdateRequest(BaseModel):
    format_id: Optional[str] = None
    policy: Optional[Dict[str, Any]] = None
    policies: Optional[Dict[str, Any]] = None

@router.get("/cdr-policies")
def get_cdr_policies():
    """Retrieve format-specific CDR and sanitization policies."""
    return {"success": True, "policies": settings_store.get_cdr_policies()}

@router.post("/cdr-policies")
def save_cdr_policies(
    req: CdrPolicyUpdateRequest,
    admin=Depends(require_admin)
):
    """Update CDR policy for one format or all formats."""
    if req.policies is not None:
        updated = settings_store.set_cdr_policies(req.policies)
        return {"success": True, "policies": updated}
    elif req.format_id and req.policy is not None:
        updated = settings_store.update_cdr_policy(req.format_id, req.policy)
        return {"success": True, "policies": updated}
    else:
        raise HTTPException(status_code=400, detail="Must provide 'policies' or both 'format_id' and 'policy'")


