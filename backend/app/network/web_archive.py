"""
Historical Web Archive & Website Evolution.
Queries the Wayback Machine (archive.org) Availability and CDX APIs to inspect historical
domain snapshots, first/last seen timelines, status codes, and detect dormant domain revival / hijacking.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
from app.core.logging_config import logger


class WebArchiveInspector:
    """
    Inspects historical snapshots of a domain or URL via the Wayback Machine APIs.
    Combines high-speed edge availability checks with deep CDX historical lookups,
    handling both apex domains and www-prefixed canonical variations.
    """

    AVAILABILITY_API_URL = "https://archive.org/wayback/available"
    # Note: Using http:// for CDX to bypass intermittent TLS refusal on 207.241.237.3:443
    CDX_API_URL = "http://web.archive.org/cdx/search/cdx"

    @classmethod
    def inspect(cls, domain_or_url: str, timeout: float = 8.5) -> Dict[str, Any]:
        clean_target = domain_or_url.strip().lower().rstrip("/")
        # Remove scheme if present
        if "://" in clean_target:
            clean_target = clean_target.split("://", 1)[1]
        host_target = clean_target.split("/")[0] if "/" in clean_target else clean_target

        result: Dict[str, Any] = {
            "target": clean_target,
            "archived": False,
            "snapshot_count": 0,
            "first_seen": None,
            "last_seen": None,
            "age_days": None,
            "dormant_revival_detected": False,
            "revival_gap_days": None,
            "status_code_distribution": {},
            "recent_snapshots": [],
            "risk_flags": [],
            "wayback_calendar_url": f"https://web.archive.org/web/*/{clean_target}",
            "api_status": "pending",
            "api_status_code": None,
            "api_error_detail": None,
        }

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # Many sites (e.g. folksam.se) are archived primarily under www.domain.tld or apex
        candidates = [clean_target]
        if not clean_target.startswith("www.") and "." in clean_target:
            candidates.append(f"www.{clean_target}")
        elif clean_target.startswith("www."):
            candidates.append(clean_target[4:])

        matched_target = clean_target
        api_200_seen = False
        api_error_code = None
        api_error_note = None

        # ---------------------------------------------------------
        # Phase 1: High-Speed Availability Lookup (archive.org edge cache)
        # ---------------------------------------------------------
        phase1_timeout = min(6.5, max(4.0, timeout * 0.75))
        with httpx.Client(timeout=phase1_timeout, follow_redirects=True, headers=browser_headers) as client:
            for cand in candidates:
                try:
                    avail_resp = client.get(cls.AVAILABILITY_API_URL, params={"url": cand})
                    if avail_resp.status_code == 200:
                        api_200_seen = True
                        avail_data = avail_resp.json()
                        closest = (avail_data.get("archived_snapshots") or {}).get("closest") or {}
                        if closest.get("available"):
                            result["archived"] = True
                            matched_target = cand
                            result["wayback_calendar_url"] = f"https://web.archive.org/web/*/{cand}"
                            closest_ts = closest.get("timestamp")
                            parsed_dt = None
                            if closest_ts and len(closest_ts) >= 8:
                                try:
                                    parsed_dt = datetime.strptime(closest_ts[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                                    result["last_seen"] = parsed_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                                except Exception:
                                    result["last_seen"] = closest_ts

                            result["snapshot_count"] = max(result["snapshot_count"], 1)
                            result["recent_snapshots"].append({
                                "timestamp": closest_ts,
                                "date": result["last_seen"] or closest_ts,
                                "status_code": closest.get("status", "200"),
                                "mimetype": "text/html",
                                "digest": None,
                                "archive_url": closest.get("url", f"https://web.archive.org/web/{closest_ts}/{cand}")
                            })
                            break
                    elif avail_resp.status_code in (503, 502, 504, 429):
                        api_error_code = avail_resp.status_code
                        api_error_note = f"Wayback Availability API returned HTTP {avail_resp.status_code} (Service Unavailable / Throttled)"
                except (httpx.TimeoutException, httpx.ConnectError) as te:
                    logger.debug(f"Wayback availability lookup note for {cand}: {te}")
                    if not api_error_code:
                        api_error_code = 504
                        api_error_note = "Wayback Machine connection timed out or was refused"
                except Exception as e:
                    logger.debug(f"Wayback availability lookup note for {cand}: {e}")

        # ---------------------------------------------------------
        # Phase 2: Forward CDX Timeline Index Query (Earliest Snapshots)
        # ---------------------------------------------------------
        cdx_targets = [matched_target]
        if matched_target != clean_target and clean_target not in cdx_targets:
            cdx_targets.append(clean_target)
        elif matched_target == clean_target and len(candidates) > 1:
            cdx_targets.append(candidates[1])

        with httpx.Client(timeout=timeout, follow_redirects=True, headers=browser_headers) as client:
            for cand in cdx_targets:
                try:
                    params = {
                        "url": cand,
                        "output": "json",
                        "fl": "timestamp,original,mimetype,statuscode,digest,length",
                        "limit": "25"
                    }
                    resp = client.get(cls.CDX_API_URL, params=params)
                    if resp.status_code == 200:
                        api_200_seen = True
                        data = resp.json()
                        if data and len(data) > 1:
                            headers = data[0]
                            rows = data[1:]

                            result["archived"] = True
                            result["snapshot_count"] = max(result["snapshot_count"], len(rows))
                            status_counts: Dict[str, int] = {}
                            timestamps = []

                            for r in rows:
                                row_dict = dict(zip(headers, r))
                                ts_str = row_dict.get("timestamp")
                                status = row_dict.get("statuscode", "unknown")
                                status_counts[status] = status_counts.get(status, 0) + 1

                                parsed_dt = None
                                if ts_str and len(ts_str) >= 8:
                                    try:
                                        parsed_dt = datetime.strptime(ts_str[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                                        timestamps.append(parsed_dt)
                                    except Exception:
                                        pass

                                if not any(s.get("timestamp") == ts_str for s in result["recent_snapshots"]):
                                    result["recent_snapshots"].append({
                                        "timestamp": ts_str,
                                        "date": parsed_dt.strftime("%Y-%m-%d %H:%M:%S UTC") if parsed_dt else ts_str,
                                        "status_code": status,
                                        "mimetype": row_dict.get("mimetype"),
                                        "digest": row_dict.get("digest"),
                                        "archive_url": f"https://web.archive.org/web/{ts_str}/{row_dict.get('original', cand)}"
                                    })

                            result["status_code_distribution"] = status_counts

                            if timestamps:
                                timestamps.sort()
                                first_dt = timestamps[0]
                                now_dt = datetime.now(timezone.utc)

                                result["first_seen"] = first_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                                if not result["last_seen"]:
                                    result["last_seen"] = timestamps[-1].strftime("%Y-%m-%d %H:%M:%S UTC")

                                result["age_days"] = (now_dt - first_dt).days

                                max_gap_days = 0
                                for i in range(len(timestamps) - 1):
                                    gap = (timestamps[i+1] - timestamps[i]).days
                                    if gap > max_gap_days:
                                        max_gap_days = gap

                                days_since_last = (now_dt - timestamps[-1]).days
                                if max_gap_days > 730 and days_since_last < 730:
                                    result["dormant_revival_detected"] = True
                                    result["revival_gap_days"] = max_gap_days
                                    result["risk_flags"].append({
                                        "id": "DORMANT_DOMAIN_REVIVAL",
                                        "severity": "HIGH",
                                        "title": "Dormant Domain Revival Detected",
                                        "description": f"Domain was inactive/dormant for {max_gap_days // 365} years before recent activity. Common tactic for repurposing expired domains for malware C2 or brand impersonation."
                                    })
                            break
                    elif resp.status_code in (503, 502, 504, 429):
                        api_error_code = resp.status_code
                        api_error_note = f"Wayback CDX API returned HTTP {resp.status_code} (Service Unavailable / Throttled)"
                except (httpx.TimeoutException, httpx.ConnectError) as te:
                    logger.debug(f"Wayback CDX lookup note for {cand}: {te}")
                    if not api_error_code:
                        api_error_code = 504
                        api_error_note = "Wayback CDX connection timed out or was refused"
                except Exception as e:
                    logger.debug(f"Wayback CDX lookup note for {cand}: {e}")

        # Determine definitive API status
        if result["archived"]:
            result["api_status"] = "available"
        elif api_200_seen:
            result["api_status"] = "verified_not_archived"
        elif api_error_code:
            result["api_status"] = "service_unavailable"
            result["api_status_code"] = api_error_code
            result["api_error_detail"] = api_error_note or "Wayback Machine API is temporarily offline (HTTP 503)."
        else:
            result["api_status"] = "service_unavailable"
            result["api_error_detail"] = "Could not contact Wayback Machine API endpoints."

        # Fallback if archived was confirmed via Phase 1 but CDX failed/timed out
        if result["archived"] and not result["first_seen"]:
            result["first_seen"] = "Indexed in Wayback Machine"

        if result["recent_snapshots"]:
            result["recent_snapshots"].sort(key=lambda s: str(s.get("timestamp") or ""), reverse=True)

        return result
