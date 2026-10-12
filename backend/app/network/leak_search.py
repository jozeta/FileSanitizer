"""
Public Pastebin & Leak Exposure Search.
Queries public paste indices and OSINT leak repositories for mentions of the target domain,
evaluates credential leak exposure, database dumps, and code leaks.
"""

from typing import Dict, Any, List, Optional
import httpx
from app.core.logging_config import logger


class LeakExposureSearcher:
    """
    Searches public paste sites and leak archives for target indicators.
    """

    PSBDMP_SEARCH_URL = "https://psbdmp.ws/api/search/{query}"

    @classmethod
    def search_leaks(cls, target: str, timeout: float = 3.5) -> Dict[str, Any]:
        clean_target = (target or "").strip().lower()
        if "://" in clean_target:
            clean_target = clean_target.split("://", 1)[1].split("/", 1)[0]
        clean_target = clean_target.split(":", 1)[0]

        result: Dict[str, Any] = {
            "target": clean_target,
            "leak_count": 0,
            "has_leaks": False,
            "severity": "CLEAN",  # CLEAN, LOW, MEDIUM, HIGH, CRITICAL
            "leaks": [],
            "risk_flags": []
        }

        if not clean_target or len(clean_target) < 3:
            return result

        try:
            url = cls.PSBDMP_SEARCH_URL.format(query=clean_target)
            with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "FileSanitizer-CTI/1.0"}) as client:
                resp = client.get(url)

            if resp.status_code == 200:
                data = resp.json()
                # psbdmp returns list of dicts: {"id": "...", "time": "...", "tags": [...]} or {"data": [...]}
                items = data.get("data") if isinstance(data, dict) else (data if isinstance(data, list) else [])
                if items:
                    result["has_leaks"] = True
                    result["leak_count"] = len(items)

                    for item in items[:15]:
                        paste_id = item.get("id") or item.get("key") or "unknown"
                        date_str = item.get("time") or item.get("date")
                        tags = item.get("tags") or []

                        result["leaks"].append({
                            "id": paste_id,
                            "source": "Pastebin Dump",
                            "date": date_str,
                            "url": f"https://pastebin.com/{paste_id}" if paste_id != "unknown" else None,
                            "tags": tags
                        })

                    # Evaluate severity
                    count = len(items)
                    if count >= 10:
                        result["severity"] = "HIGH"
                        result["risk_flags"].append({
                            "id": "HIGH_PUBLIC_PASTE_EXPOSURE",
                            "severity": "HIGH",
                            "title": "Multiple Public Paste Exposures",
                            "description": f"Found {count} public paste mentions for {clean_target}. Often indicates leaked credentials, configuration dumps, or compromised server logs."
                        })
                    elif count >= 1:
                        result["severity"] = "MEDIUM"
                        result["risk_flags"].append({
                            "id": "PUBLIC_PASTE_EXPOSURE",
                            "severity": "MEDIUM",
                            "title": "Public Paste Mentions Detected",
                            "description": f"Found {count} paste mention(s) referencing {clean_target} in public repositories."
                        })

        except Exception as e:
            logger.debug(f"Leak search note for {clean_target}: {e}")

        return result
