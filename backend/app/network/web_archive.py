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
    handling apex domains, www-prefixed canonical variations, wildcard paths, and
    API downtime / throttling gracefully.
    """

    AVAILABILITY_API_URL = "https://archive.org/wayback/available"
    # Try HTTPS CDX first, with HTTP fallback if 443 connection fails
    CDX_API_URLS = [
        "https://web.archive.org/cdx/search/cdx",
        "http://web.archive.org/cdx/search/cdx",
    ]

    @classmethod
    def inspect(cls, domain_or_url: str, timeout: float = 8.5) -> Dict[str, Any]:
        clean_target = domain_or_url.strip().lower().rstrip("/")
        # Remove scheme if present
        if "://" in clean_target:
            clean_target = clean_target.split("://", 1)[1]
        host_target = clean_target.split("/")[0] if "/" in clean_target else clean_target

        # The canonical Wayback Machine URL syntax for domain browsing requires http:// and wildcard *
        # e.g. https://web.archive.org/web/*/http://kpa.se* (matches all captures across http, https, and subpaths)
        primary_calendar = f"https://web.archive.org/web/*/http://{host_target}*"
        https_calendar = f"https://web.archive.org/web/*/https://{host_target}*"
        www_target = f"www.{host_target}" if not host_target.startswith("www.") else host_target[4:]
        www_calendar = f"https://web.archive.org/web/*/http://{www_target}*"

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
            "wayback_calendar_url": primary_calendar,
            "wayback_https_calendar_url": https_calendar,
            "wayback_www_calendar_url": www_calendar,
            "api_status": "pending",
            "api_status_code": None,
            "api_error_detail": None,
        }

        browser_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
        }

        # Candidate variants (apex, www, http, https)
        candidates = [host_target]
        if not host_target.startswith("www.") and "." in host_target:
            candidates.append(f"www.{host_target}")
        elif host_target.startswith("www."):
            candidates.append(host_target[4:])

        matched_target = host_target
        cdx_queried_successfully = False
        cdx_clean_empty = False
        api_error_code = None
        api_error_note = None

        # ---------------------------------------------------------
        # Phase 1: High-Speed Availability Lookup (archive.org edge cache)
        # ---------------------------------------------------------
        phase1_timeout = min(2.0, max(1.2, timeout * 0.25))
        # Build primary candidates for Availability API (http scheme matches all protocols in Wayback)
        avail_candidates = [f"http://{cand}" for cand in candidates]

        host_unreachable = False
        with httpx.Client(timeout=phase1_timeout, follow_redirects=True, headers=browser_headers) as client:
            for cand_url in avail_candidates:
                try:
                    avail_resp = client.get(cls.AVAILABILITY_API_URL, params={"url": cand_url})
                    if avail_resp.status_code == 200:
                        try:
                            avail_data = avail_resp.json()
                            closest = (avail_data.get("archived_snapshots") or {}).get("closest") or {}
                            if closest.get("available"):
                                result["archived"] = True
                                matched_target = cand_url
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
                                    "archive_url": closest.get("url", f"https://web.archive.org/web/{closest_ts}/{cand_url}")
                                })
                                break
                        except Exception:
                            # Response was HTML ("Temporarily Offline") rather than valid JSON
                            api_error_code = 503
                            api_error_note = "Wayback Availability API returned non-JSON offline notice"
                    elif avail_resp.status_code in (503, 502, 504, 429):
                        api_error_code = avail_resp.status_code
                        api_error_note = f"Wayback Availability API returned HTTP {avail_resp.status_code} (Service Unavailable / Throttled)"
                except httpx.ConnectError as ce:
                    logger.debug(f"Wayback host unreachable/connection refused for {cand_url}: {ce}")
                    api_error_code = 502
                    api_error_note = "Wayback Machine connection refused (Archive.org edge is currently unreachable)"
                    host_unreachable = True
                    break
                except httpx.TimeoutException as te:
                    logger.debug(f"Wayback availability lookup timeout for {cand_url}: {te}")
                    if not api_error_code:
                        api_error_code = 504
                        api_error_note = "Wayback Machine connection timed out"
                    # Break immediately if Wayback edge times out to prevent stacking delay
                    host_unreachable = True
                    break
                except Exception as e:
                    logger.debug(f"Wayback availability lookup note for {cand_url}: {e}")

        # ---------------------------------------------------------
        # Phase 2: Forward CDX Timeline Index Query (Earliest Snapshots & Wildcard Match)
        # ---------------------------------------------------------
        cdx_targets = [host_target]
        if not host_target.startswith("www.") and "." in host_target:
            cdx_targets.append(f"www.{host_target}")

        phase2_timeout = min(3.0, max(2.0, timeout * 0.4))
        if not host_unreachable:
            with httpx.Client(timeout=phase2_timeout, follow_redirects=True, headers=browser_headers) as client:
                for cand in cdx_targets:
                    if result["archived"] and len(result["recent_snapshots"]) >= 10:
                        break

                    # Query CDX with wildcard pattern (e.g. kpa.se/*) to capture all historical pages
                    query_params_list = [
                        {
                            "url": f"{cand}/*",
                            "output": "json",
                            "fl": "timestamp,original,mimetype,statuscode,digest,length",
                            "limit": "50"
                        },
                        {
                            "url": cand,
                            "output": "json",
                            "fl": "timestamp,original,mimetype,statuscode,digest,length",
                            "limit": "25"
                        }
                    ]

                    cdx_endpoint_success = False
                    for params in query_params_list:
                        if cdx_endpoint_success:
                            break
                        for cdx_url in cls.CDX_API_URLS:
                            try:
                                resp = client.get(cdx_url, params=params)
                                if resp.status_code == 200:
                                    try:
                                        data = resp.json()
                                        cdx_queried_successfully = True
                                        cdx_endpoint_success = True
                                        if data and len(data) > 1:
                                            headers = data[0]
                                            rows = data[1:]

                                            result["archived"] = True
                                            result["snapshot_count"] = max(result["snapshot_count"], len(rows))
                                            status_counts: Dict[str, int] = result["status_code_distribution"]
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

                                                if not result["first_seen"] or result["first_seen"] == "Indexed in Wayback Machine":
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
                                                    if not any(rf.get("id") == "DORMANT_DOMAIN_REVIVAL" for rf in result["risk_flags"]):
                                                        result["risk_flags"].append({
                                                            "id": "DORMANT_DOMAIN_REVIVAL",
                                                            "severity": "HIGH",
                                                            "title": "Dormant Domain Revival Detected",
                                                            "description": f"Domain was inactive/dormant for {max_gap_days // 365} years before recent activity. Common tactic for repurposing expired domains for malware C2 or brand impersonation."
                                                        })
                                        else:
                                            cdx_clean_empty = True
                                        break
                                    except Exception:
                                        api_error_code = 503
                                        api_error_note = "Wayback CDX API returned non-JSON maintenance response"
                                elif resp.status_code in (503, 502, 504, 429):
                                    api_error_code = resp.status_code
                                    api_error_note = f"Wayback CDX API returned HTTP {resp.status_code} (Service Unavailable / Throttled)"
                            except httpx.ConnectError as ce:
                                logger.debug(f"Wayback CDX host unreachable for {cdx_url}: {ce}")
                                api_error_code = 502
                                api_error_note = "Wayback CDX connection refused (Archive.org edge unreachable)"
                                host_unreachable = True
                                break
                            except httpx.TimeoutException as te:
                                logger.debug(f"Wayback CDX lookup timeout for {cdx_url}: {te}")
                                if not api_error_code:
                                    api_error_code = 504
                                    api_error_note = "Wayback CDX connection timed out"
                                host_unreachable = True
                                break
                            except Exception as e:
                                logger.debug(f"Wayback CDX lookup note for {cdx_url}: {e}")
                        if host_unreachable:
                            break
                    if host_unreachable:
                        break

        # ---------------------------------------------------------
        # Phase 3: Status Determination (Avoid False Negatives on API Outages)
        # ---------------------------------------------------------
        if result["archived"]:
            result["api_status"] = "available"
        elif cdx_queried_successfully and cdx_clean_empty and not result["archived"]:
            # Only mark verified_not_archived if CDX was successfully reached and returned 0 rows
            result["api_status"] = "verified_not_archived"
        elif api_error_code or not cdx_queried_successfully:
            # CDX was not successfully reached or returned 503/timeout
            result["api_status"] = "service_unavailable"
            result["api_status_code"] = api_error_code or 503
            result["api_error_detail"] = api_error_note or "Wayback Machine API is temporarily offline or timed out."
        else:
            result["api_status"] = "service_unavailable"
            result["api_error_detail"] = "Could not contact Wayback Machine API endpoints."

        # Fallback if archived was confirmed via Phase 1 but CDX failed/timed out
        if result["archived"] and not result["first_seen"]:
            result["first_seen"] = "Indexed in Wayback Machine"

        if result["recent_snapshots"]:
            result["recent_snapshots"].sort(key=lambda s: str(s.get("timestamp") or ""), reverse=True)

        return result
