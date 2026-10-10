import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from email.utils import parsedate_to_datetime


class ForensicTimelineBuilder:
    """
    Forensic Timeline and Incident Event Reconstruction Generator.
    Correlates and chronologically orders filesystem metadata, embedded document
    timestamps, EXIF camera capture times, email transit hops, archive member dates,
    domain registration/WHOIS dates, threat intelligence first-seen dates (VirusTotal,
    CrowdStrike Falcon/Hybrid Analysis, ThreatFox, MalwareBazaar, OTX), and detected
    temporal anomalies (timestomping).
    """

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> Optional[datetime]:
        """Attempt to parse arbitrary timestamp formats (strings, epoch, zip tuples) into UTC datetime."""
        if ts_val is None:
            return None

        # Check list or tuple e.g. zipfile (YYYY, MM, DD, HH, MM, SS)
        if isinstance(ts_val, (list, tuple)) and len(ts_val) >= 3:
            try:
                parts = [int(p) for p in ts_val]
                y, m, d = parts[0], parts[1], parts[2]
                h = parts[3] if len(parts) > 3 else 0
                mi = parts[4] if len(parts) > 4 else 0
                s = parts[5] if len(parts) > 5 else 0
                return datetime(y, m, d, h, mi, s, tzinfo=timezone.utc)
            except Exception:
                pass

        # Check numeric epoch (int, float)
        if isinstance(ts_val, (int, float)):
            try:
                val = float(ts_val)
                # If milliseconds (> 1e11), convert to seconds
                if val > 1e11:
                    val = val / 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except Exception:
                return None

        if not isinstance(ts_val, str):
            return None

        clean = ts_val.strip()
        if not clean:
            return None

        # Truncate nanoseconds or 7+ fractional digits to 6 digits (microseconds) for Python strptime/fromisoformat
        clean = re.sub(r'(\.\d{6})\d+', r'\1', clean)

        # Check numeric string epoch
        if re.match(r"^\d+(\.\d+)?$", clean):
            try:
                val = float(clean)
                if val > 1e11:
                    val = val / 1000.0
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except Exception:
                pass

        # ISO and standard datetime string formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S UTC",
            "%Y:%m:%d %H:%M:%S",  # EXIF style
            "%a, %d %b %Y %H:%M:%S %z",  # RFC 2822
            "%d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%d %b %Y %H:%M:%S %Z",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(clean, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except (ValueError, TypeError):
                continue

        # Try email parsedate
        try:
            dt = parsedate_to_datetime(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Try PDF date format D:YYYYMMDDHHmmSSOHH'mm'
        pdf_match = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?", clean)
        if pdf_match:
            try:
                parts = [int(p) if p else 0 for p in pdf_match.groups()]
                dt = datetime(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], tzinfo=timezone.utc)
                return dt
            except Exception:
                pass

        return None

    @classmethod
    def generate_timeline(cls, job: Any) -> List[Dict[str, Any]]:
        """
        Extract and assemble all chronological events from the job and its analysis artifacts.
        """
        events: List[Dict[str, Any]] = []

        # 1. Job Ingestion Time
        created_at_dt = cls._parse_timestamp(getattr(job, "created_at", None))
        if created_at_dt:
            events.append({
                "timestamp": created_at_dt.isoformat(),
                "epoch": created_at_dt.timestamp(),
                "category": "system",
                "source": "FileSanitizer Ingestion",
                "event_type": "FILE_INGESTED",
                "title": f"File submitted for analysis: {getattr(job, 'filename', 'sample')}",
                "description": f"Uploaded with size {getattr(job, 'file_size', 0)} bytes, MIME {getattr(job, 'mime_type', 'unknown')}",
                "severity": "info",
                "is_anomaly": False
            })

        # 1b. Previous Submissions History (if file has been analyzed before)
        try:
            from app.core.settings_store import settings_store
            from app.core.job_manager import job_manager

            current_job_id = getattr(job, "job_id", "")
            curr_sha256 = (getattr(job, "hashes", {}) or {}).get("sha256", "").lower().strip()
            curr_md5 = (getattr(job, "hashes", {}) or {}).get("md5", "").lower().strip()
            curr_filename = (getattr(job, "original_filename", "") or getattr(job, "filename", "")).strip().lower()

            seen_history_ids = {current_job_id}
            history_entries: List[Dict[str, Any]] = []

            # Check persistent upload history records
            for entry in settings_store.get_upload_history():
                eid = entry.get("job_id", "")
                if not eid or eid in seen_history_ids:
                    continue
                e_sha = str(entry.get("sha256", "")).lower().strip()
                e_md5 = str(entry.get("md5", "")).lower().strip()
                e_name = str(entry.get("filename", "")).strip().lower()

                matched = False
                if curr_sha256 and e_sha and curr_sha256 == e_sha:
                    matched = True
                elif curr_md5 and e_md5 and curr_md5 == e_md5:
                    matched = True
                elif not curr_sha256 and curr_filename and e_name == curr_filename:
                    matched = True

                if matched:
                    seen_history_ids.add(eid)
                    history_entries.append({
                        "job_id": eid,
                        "uploaded_at": entry.get("uploaded_at"),
                        "filename": entry.get("filename") or getattr(job, "filename", "file"),
                        "risk_level": entry.get("risk_level", "UNKNOWN"),
                        "verdict": entry.get("verdict", "Scanned"),
                        "findings_count": entry.get("findings_count", 0),
                        "vt_ratio": entry.get("vt_ratio") or entry.get("vt_score")
                    })

            # Check active in-memory jobs from job_manager
            if hasattr(job_manager, "_jobs") and isinstance(job_manager._jobs, dict):
                for mem_id, mem_job in job_manager._jobs.items():
                    if mem_id in seen_history_ids or mem_id == current_job_id:
                        continue
                    m_sha = (getattr(mem_job, "hashes", {}) or {}).get("sha256", "").lower().strip()
                    m_md5 = (getattr(mem_job, "hashes", {}) or {}).get("md5", "").lower().strip()
                    m_name = (getattr(mem_job, "original_filename", "") or getattr(mem_job, "filename", "")).strip().lower()

                    matched = False
                    if curr_sha256 and m_sha and curr_sha256 == m_sha:
                        matched = True
                    elif curr_md5 and m_md5 and curr_md5 == m_md5:
                        matched = True
                    elif not curr_sha256 and curr_filename and m_name == curr_filename:
                        matched = True

                    if matched:
                        seen_history_ids.add(mem_id)
                        risk_level = getattr(mem_job.risk, "level", "UNKNOWN") if getattr(mem_job, "risk", None) else "UNKNOWN"
                        verdict = getattr(mem_job.risk, "verdict", None) if getattr(mem_job, "risk", None) else None
                        history_entries.append({
                            "job_id": mem_id,
                            "uploaded_at": getattr(mem_job, "created_at", None),
                            "filename": getattr(mem_job, "original_filename", None) or getattr(mem_job, "filename", "file"),
                            "risk_level": risk_level,
                            "verdict": verdict or risk_level,
                            "findings_count": len(getattr(mem_job, "findings", []) or []),
                            "vt_ratio": (getattr(mem_job, "virustotal", {}) or {}).get("positives")
                        })

            if history_entries and events and events[0].get("event_type") == "FILE_INGESTED":
                events[0]["description"] += f" • Note: File was previously submitted {len(history_entries)} time{'s' if len(history_entries) > 1 else ''} to FileSanitizer"

            for h in history_entries:
                dt_h = cls._parse_timestamp(h.get("uploaded_at"))
                if dt_h:
                    risk_str = h.get("risk_level", "UNKNOWN")
                    verdict_str = h.get("verdict") or risk_str
                    f_count = h.get("findings_count", 0)
                    h_name = h.get("filename")
                    vt_info = f", VT: {h.get('vt_ratio')}" if h.get("vt_ratio") else ""

                    sev = "info"
                    if risk_str in ["MALWARE", "CRITICAL"] or "MALICIOUS" in str(verdict_str).upper():
                        sev = "critical"
                    elif "HIGH" in risk_str.upper():
                        sev = "high"
                    elif "MEDIUM" in risk_str.upper() or "SUSPICIOUS" in str(verdict_str).upper():
                        sev = "warning"

                    events.append({
                        "timestamp": dt_h.isoformat(),
                        "epoch": dt_h.timestamp(),
                        "category": "history",
                        "source": "Submission History",
                        "event_type": "PREVIOUS_SUBMISSION",
                        "title": f"Previous Submission: {h_name} ({verdict_str})",
                        "description": (
                            f"Identical file was previously uploaded and analyzed on {dt_h.strftime('%Y-%m-%d %H:%M:%S UTC')}. "
                            f"Result: {risk_str} ({verdict_str}), Security Findings: {f_count}{vt_info}. "
                            f"Historical Job ID: {h.get('job_id')}."
                        ),
                        "severity": sev,
                        "is_anomaly": False
                    })
        except Exception as he:
            pass

        # 2. Filesystem & General Metadata Timestamps (for all file formats EXCEPT msg and eml)
        is_email = getattr(job, "category", "") == "email" or str(getattr(job, "filename", "")).lower().endswith((".msg", ".eml", ".mbox"))
        metadata = getattr(job, "metadata", None)
        dt_doc_created = None
        dt_doc_mod = None

        if not is_email and metadata:
            def _extract_field_map(val: Any) -> Dict[str, str]:
                if isinstance(val, dict):
                    return {str(k).lower(): str(v) for k, v in val.items()}
                elif isinstance(val, list):
                    res = {}
                    for item in val:
                        if hasattr(item, "name") and hasattr(item, "value"):
                            res[str(item.name).lower()] = str(item.value)
                        elif isinstance(item, dict) and "name" in item and "value" in item:
                            res[str(item["name"]).lower()] = str(item["value"])
                    return res
                return {}

            meta_dict = metadata.model_dump() if hasattr(metadata, "model_dump") else (metadata if isinstance(metadata, dict) else {})
            file_meta = _extract_field_map(meta_dict.get("file", []) or meta_dict.get("general", []))
            doc_meta = _extract_field_map(meta_dict.get("document", []))
            camera_meta = _extract_field_map(meta_dict.get("camera", []))

            # Document / File Creation
            doc_created = (
                doc_meta.get("created") or doc_meta.get("creation date") or doc_meta.get("creation_date") 
                or doc_meta.get("dcterms:created") or doc_meta.get("date created") or file_meta.get("file creation date/time")
                or file_meta.get("creation_date") or file_meta.get("created")
            )
            dt_doc_created = cls._parse_timestamp(doc_created)
            if dt_doc_created:
                events.append({
                    "timestamp": dt_doc_created.isoformat(),
                    "epoch": dt_doc_created.timestamp(),
                    "category": "document",
                    "source": "Document Metadata",
                    "event_type": "DOCUMENT_CREATED",
                    "title": f"File / Document Created: {getattr(job, 'filename', 'file')}",
                    "description": f"Created by author: {doc_meta.get('creator') or doc_meta.get('author') or 'Unknown'}",
                    "severity": "info",
                    "is_anomaly": False
                })

            # Document / File Modification
            doc_modified = (
                doc_meta.get("modified") or doc_meta.get("mod date") or doc_meta.get("mod_date") 
                or doc_meta.get("dcterms:modified") or doc_meta.get("last modified") or doc_meta.get("date modified")
                or file_meta.get("file modification date/time") or file_meta.get("modify_date") or file_meta.get("modified")
            )
            dt_doc_mod = cls._parse_timestamp(doc_modified)
            if dt_doc_mod:
                events.append({
                    "timestamp": dt_doc_mod.isoformat(),
                    "epoch": dt_doc_mod.timestamp(),
                    "category": "document",
                    "source": "Document Metadata",
                    "event_type": "DOCUMENT_MODIFIED",
                    "title": f"File / Document Modified: {getattr(job, 'filename', 'file')}",
                    "description": f"Last saved / modified by: {doc_meta.get('last_modified_by') or doc_meta.get('last modified by') or 'Unknown'}",
                    "severity": "info",
                    "is_anomaly": False
                })

            # Camera / EXIF Capture Time
            exif_time = (
                camera_meta.get("date_time_original") or camera_meta.get("datetimeoriginal") 
                or camera_meta.get("date/time original") or camera_meta.get("datetimedigitized")
            )
            dt_exif = cls._parse_timestamp(exif_time)
            if dt_exif:
                events.append({
                    "timestamp": dt_exif.isoformat(),
                    "epoch": dt_exif.timestamp(),
                    "category": "media",
                    "source": "EXIF Sensor Metadata",
                    "event_type": "PHOTO_CAPTURED",
                    "title": f"Image Sensor Capture: {camera_meta.get('make', '')} {camera_meta.get('model', '')}".strip(),
                    "description": f"Captured at {exif_time}. Software: {camera_meta.get('software', 'Standard Firmware')}",
                    "severity": "info",
                    "is_anomaly": False
                })

        # Physical filesystem timestamps fallback (for non-email files)
        if not is_email:
            try:
                from app.core.job_manager import job_manager
                ws = job_manager.get_workspace(getattr(job, "job_id", ""))
                if ws:
                    p = ws.original_file_path(job.filename)
                    if p.exists():
                        st = p.stat()
                        birthtime = getattr(st, "st_birthtime", None) or getattr(st, "st_ctime", None)
                        if not dt_doc_created and birthtime:
                            dt_fs_c = datetime.fromtimestamp(birthtime, tz=timezone.utc)
                            events.append({
                                "timestamp": dt_fs_c.isoformat(),
                                "epoch": dt_fs_c.timestamp(),
                                "category": "filesystem",
                                "source": "Filesystem Metadata",
                                "event_type": "FILE_CREATED",
                                "title": f"File Created: {job.filename}",
                                "description": f"Filesystem creation date: {dt_fs_c.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                "severity": "info",
                                "is_anomaly": False
                            })
                            dt_doc_created = dt_fs_c
                        if not dt_doc_mod and st.st_mtime:
                            dt_fs_m = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                            events.append({
                                "timestamp": dt_fs_m.isoformat(),
                                "epoch": dt_fs_m.timestamp(),
                                "category": "filesystem",
                                "source": "Filesystem Metadata",
                                "event_type": "FILE_MODIFIED",
                                "title": f"File Modified: {job.filename}",
                                "description": f"Filesystem modification date: {dt_fs_m.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                "severity": "info",
                                "is_anomaly": False
                            })
                            dt_doc_mod = dt_fs_m
            except Exception:
                pass

        # Check Timestomping Anomaly in Document (Created > Modified)
        if dt_doc_created and dt_doc_mod and dt_doc_created > dt_doc_mod:
            delta_sec = int((dt_doc_created - dt_doc_mod).total_seconds())
            events.append({
                "timestamp": dt_doc_created.isoformat(),
                "epoch": dt_doc_created.timestamp(),
                "category": "anomaly",
                "source": "Forensic Anomaly Detector",
                "event_type": "TIMESTOMPING_INVERTED_DATES",
                "title": f"Anti-Forensic Timestomping: Created > Modified ({delta_sec}s discrepancy)",
                "description": "The file creation timestamp is chronologically newer than its modification timestamp, indicating timestamp tampering or synthetic artifact fabrication.",
                "severity": "critical",
                "is_anomaly": True
            })

        # 3. Office Document Metadata (OpenXML docProps/core.xml)
        office_info = getattr(job, "office_info", None)
        if office_info and isinstance(office_info, dict):
            ometa = office_info.get("metadata", {})
            if isinstance(ometa, dict):
                o_created = ometa.get("created")
                dt_o_created = cls._parse_timestamp(o_created)
                if dt_o_created and not dt_doc_created:
                    events.append({
                        "timestamp": dt_o_created.isoformat(),
                        "epoch": dt_o_created.timestamp(),
                        "category": "document",
                        "source": "Office OpenXML Metadata",
                        "event_type": "OFFICE_DOCUMENT_CREATED",
                        "title": "Office Document Authoring Timestamp",
                        "description": f"Author: {ometa.get('creator', 'Unknown')}, Title: {ometa.get('title', 'Untitled')}",
                        "severity": "info",
                        "is_anomaly": False
                    })
                o_mod = ometa.get("modified")
                dt_o_mod = cls._parse_timestamp(o_mod)
                if dt_o_mod and not dt_doc_mod:
                    events.append({
                        "timestamp": dt_o_mod.isoformat(),
                        "epoch": dt_o_mod.timestamp(),
                        "category": "document",
                        "source": "Office OpenXML Metadata",
                        "event_type": "OFFICE_DOCUMENT_MODIFIED",
                        "title": "Office Document Last Saved Timestamp",
                        "description": f"Last modified by: {ometa.get('lastModifiedBy', 'Unknown')}",
                        "severity": "info",
                        "is_anomaly": False
                    })

        # 4. PDF Document Metadata
        pdf_info = getattr(job, "pdf_info", None)
        if pdf_info and isinstance(pdf_info, dict):
            pmeta = pdf_info.get("metadata", {})
            if isinstance(pmeta, dict):
                p_created = pmeta.get("creationDate") or pmeta.get("CreationDate")
                dt_p_created = cls._parse_timestamp(p_created)
                if dt_p_created and not dt_doc_created:
                    events.append({
                        "timestamp": dt_p_created.isoformat(),
                        "epoch": dt_p_created.timestamp(),
                        "category": "document",
                        "source": "PDF Document Catalog",
                        "event_type": "PDF_DOCUMENT_CREATED",
                        "title": "PDF Document Creation Timestamp",
                        "description": f"Producer: {pmeta.get('producer', 'Unknown')}, Creator: {pmeta.get('creator', 'Unknown')}",
                        "severity": "info",
                        "is_anomaly": False
                    })
                p_mod = pmeta.get("modDate") or pmeta.get("ModDate")
                dt_p_mod = cls._parse_timestamp(p_mod)
                if dt_p_mod and not dt_doc_mod:
                    events.append({
                        "timestamp": dt_p_mod.isoformat(),
                        "epoch": dt_p_mod.timestamp(),
                        "category": "document",
                        "source": "PDF Document Catalog",
                        "event_type": "PDF_DOCUMENT_MODIFIED",
                        "title": "PDF Document Last Modified Timestamp",
                        "description": f"Author: {pmeta.get('author', 'Unknown')}",
                        "severity": "info",
                        "is_anomaly": False
                    })

        # 5. Email Transit Hops, Headers, and Attachment Payloads
        email_info = getattr(job, "email_info", None)
        queried_domains = set()

        if email_info and isinstance(email_info, dict):
            # Email Sent Date
            headers = email_info.get("headers", {})
            email_date_str = headers.get("date") or headers.get("Date")
            dt_email_sent = cls._parse_timestamp(email_date_str)
            if dt_email_sent:
                events.append({
                    "timestamp": dt_email_sent.isoformat(),
                    "epoch": dt_email_sent.timestamp(),
                    "category": "email",
                    "source": "Email Header (Date:)",
                    "event_type": "EMAIL_ORIGIN_DISPATCH",
                    "title": f"Email Dispatched from {headers.get('from', 'Sender')}",
                    "description": f"Subject: '{email_info.get('subject', '')}'",
                    "severity": "info",
                    "is_anomaly": False
                })

            # Transit hops
            hops = email_info.get("transit_hops") or email_info.get("received_hops", [])
            for idx, hop in enumerate(hops):
                hop_ts = hop.get("timestamp") or hop.get("date")
                dt_hop = cls._parse_timestamp(hop_ts)
                if dt_hop:
                    from_host = hop.get("from_host") or hop.get("from") or "MTA"
                    by_host = hop.get("by_host") or hop.get("by") or "Relay"
                    hop_num = hop.get("hop_number", idx + 1)
                    ip = hop.get("ip") or ""
                    country = hop.get("country", "")
                    delay = hop.get("delay_seconds")
                    desc = f"Hop #{hop_num} via {hop.get('protocol', 'SMTP')}."
                    if ip:
                        desc += f" IP: {ip} ({country or 'Public'})."
                    if delay is not None:
                        desc += f" Relay delay: {delay}s."
                    events.append({
                        "timestamp": dt_hop.isoformat(),
                        "epoch": dt_hop.timestamp(),
                        "category": "email",
                        "source": f"Received Hop #{hop_num}",
                        "event_type": "EMAIL_TRANSIT_RELAY",
                        "title": f"Relayed: {from_host} -> {by_host}",
                        "description": desc,
                        "severity": "info",
                        "is_anomaly": False
                    })

            # Email Attachments & Nested Archive Payloads
            email_attachments = email_info.get("attachments", [])
            for att in email_attachments:
                att_date = att.get("date") or att.get("timestamp")
                dt_att = cls._parse_timestamp(att_date)
                if dt_att:
                    events.append({
                        "timestamp": dt_att.isoformat(),
                        "epoch": dt_att.timestamp(),
                        "category": "archive",
                        "source": "Email Attachment",
                        "event_type": "ATTACHMENT_TIMESTAMP",
                        "title": f"Email Attachment: {att.get('filename', 'file')}",
                        "description": f"Attachment size: {att.get('size', 0)} bytes.",
                        "severity": "warning" if att.get("is_dangerous") else "info",
                        "is_anomaly": False
                    })

                # Check nested archive members inside attachment (e.g. JS dropper inside ZIP)
                inner_files = att.get("inner_files", [])
                for inner in inner_files:
                    inner_dt = cls._parse_timestamp(inner.get("date_time") or inner.get("date") or inner.get("timestamp"))
                    if inner_dt:
                        events.append({
                            "timestamp": inner_dt.isoformat(),
                            "epoch": inner_dt.timestamp(),
                            "category": "archive",
                            "source": f"Attachment Archive ({att.get('filename', 'container')})",
                            "event_type": "ATTACHMENT_PAYLOAD_AUTHORED",
                            "title": f"Archive Payload Authored: {inner.get('filename')}",
                            "description": f"File member compressed in '{att.get('filename')}'. Size: {inner.get('size', 0)} bytes. Dangerous extension: {'YES' if inner.get('is_dangerous') else 'No'}.",
                            "severity": "critical" if inner.get("is_dangerous") else "info",
                            "is_anomaly": False
                        })

            # Lookup email sender domain registration
            from_str = email_info.get("from") or headers.get("from", "")
            sender_domain_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_str)
            if sender_domain_match:
                s_dom = sender_domain_match.group(1).lower().strip(".")
                if s_dom not in queried_domains:
                    queried_domains.add(s_dom)
                    try:
                        from app.analyzers.domain_analyzer import DomainAnalyzer
                        rdap_res = DomainAnalyzer.query_rdap_whois(s_dom)
                        reg_date = rdap_res.get("registration_date") or rdap_res.get("creation_date")
                        dt_s_reg = cls._parse_timestamp(reg_date)
                        if dt_s_reg:
                            events.append({
                                "timestamp": dt_s_reg.isoformat(),
                                "epoch": dt_s_reg.timestamp(),
                                "category": "network",
                                "source": "WHOIS / RDAP Registrar",
                                "event_type": "EMAIL_SENDER_DOMAIN_REGISTERED",
                                "title": f"Email Sender Domain Registered: @{s_dom}",
                                "description": f"Sender domain registered with {rdap_res.get('registrar', 'Registrar')}. Sender: {from_str}",
                                "severity": "info",
                                "is_anomaly": False
                            })
                    except Exception:
                        pass

        # 6. Embedded & Archive Files (creation & modify dates for each member file)
        embedded_files = getattr(job, "embedded_files", []) or []
        for emb in embedded_files:
            emb_name = emb.get("name") or emb.get("filename") or "embedded_payload"
            # Creation date
            c_date = emb.get("created_date") or emb.get("date") or emb.get("created_at") or emb.get("timestamp") or emb.get("date_time")
            dt_c = cls._parse_timestamp(c_date)
            if dt_c:
                events.append({
                    "timestamp": dt_c.isoformat(),
                    "epoch": dt_c.timestamp(),
                    "category": "embedded",
                    "source": f"Embedded Payload ({emb.get('parent_format', 'Container')})",
                    "event_type": "EMBEDDED_FILE_CREATED",
                    "title": f"Embedded File Created: {emb_name}",
                    "description": f"Origin: {emb.get('origin_stream', '')}, Size: {emb.get('size', 0)} bytes, Type: {emb.get('mime_type', 'data')}",
                    "severity": "warning" if emb.get("is_dangerous") else "info",
                    "is_anomaly": False
                })
            # Modify date
            m_date = emb.get("modified_date")
            dt_m = cls._parse_timestamp(m_date)
            if dt_m and dt_m != dt_c:
                events.append({
                    "timestamp": dt_m.isoformat(),
                    "epoch": dt_m.timestamp(),
                    "category": "embedded",
                    "source": f"Embedded Payload ({emb.get('parent_format', 'Container')})",
                    "event_type": "EMBEDDED_FILE_MODIFIED",
                    "title": f"Embedded File Modified: {emb_name}",
                    "description": f"Origin: {emb.get('origin_stream', '')}, Size: {emb.get('size', 0)} bytes",
                    "severity": "warning" if emb.get("is_dangerous") else "info",
                    "is_anomaly": False
                })

        # Archive Members (ZIP, RAR, 7z, TAR)
        archive_info = getattr(job, "archive_info", None)
        if not archive_info and hasattr(job, "analysis_data") and isinstance(getattr(job, "analysis_data"), dict):
            archive_info = job.analysis_data.get("archive")
        if archive_info and isinstance(archive_info, dict):
            arch_list = archive_info.get("file_list", [])
            for item in arch_list:
                item_name = item.get("filename")
                if not item_name:
                    continue
                # Member Creation date
                c_date = item.get("created_date") or item.get("date_time")
                dt_c = cls._parse_timestamp(c_date)
                if dt_c:
                    events.append({
                        "timestamp": dt_c.isoformat(),
                        "epoch": dt_c.timestamp(),
                        "category": "archive",
                        "source": f"Archive Container ({getattr(job, 'filename', 'Archive')})",
                        "event_type": "ARCHIVE_MEMBER_CREATED",
                        "title": f"Archive Member Created: {item_name}",
                        "description": f"Compressed: {item.get('compressed_size', 0)} bytes, Size: {item.get('size', 0)} bytes",
                        "severity": "info",
                        "is_anomaly": False
                    })
                # Member Modify date
                m_date = item.get("modified_date")
                dt_m = cls._parse_timestamp(m_date)
                if dt_m and dt_m != dt_c:
                    events.append({
                        "timestamp": dt_m.isoformat(),
                        "epoch": dt_m.timestamp(),
                        "category": "archive",
                        "source": f"Archive Container ({getattr(job, 'filename', 'Archive')})",
                        "event_type": "ARCHIVE_MEMBER_MODIFIED",
                        "title": f"Archive Member Modified: {item_name}",
                        "description": f"Compressed: {item.get('compressed_size', 0)} bytes, Size: {item.get('size', 0)} bytes",
                        "severity": "info",
                        "is_anomaly": False
                    })

        # 7. Discovered URLs & Domain Registration / Renewal / Expiration
        urls = getattr(job, "urls", []) or []
        for u in urls[:15]:  # Process up to 15 URLs
            u_dict = u if isinstance(u, dict) else (u.model_dump() if hasattr(u, "model_dump") else {})
            dom = u_dict.get("domain")
            if not dom:
                url_str = u_dict.get("url", "")
                m = re.search(r'https?://([^/:\s]+)', url_str)
                if m:
                    dom = m.group(1).lower()

            if dom and dom not in queried_domains:
                queried_domains.add(dom)
                # Check if domain_intelligence already exists on the URL record
                d_intel = u_dict.get("domain_intelligence", {})
                whois_data = d_intel.get("whois", {})
                if not whois_data:
                    try:
                        from app.analyzers.domain_analyzer import DomainAnalyzer
                        whois_data = DomainAnalyzer.query_rdap_whois(dom)
                    except Exception:
                        whois_data = {}

                reg_date = whois_data.get("registration_date") or whois_data.get("creation_date") or whois_data.get("created")
                dt_u_reg = cls._parse_timestamp(reg_date)
                if dt_u_reg:
                    events.append({
                        "timestamp": dt_u_reg.isoformat(),
                        "epoch": dt_u_reg.timestamp(),
                        "category": "network",
                        "source": "WHOIS / RDAP Registrar",
                        "event_type": "URL_DOMAIN_REGISTERED",
                        "title": f"Discovered Link Domain Registered: {dom}",
                        "description": f"Domain was originally registered with {whois_data.get('registrar', 'Registrar')}. Referenced in: {u_dict.get('url', dom)}",
                        "severity": "info",
                        "is_anomaly": False
                    })

                upd_date = whois_data.get("updated_date") or whois_data.get("last_updated") or whois_data.get("updated")
                dt_u_upd = cls._parse_timestamp(upd_date)
                if dt_u_upd:
                    events.append({
                        "timestamp": dt_u_upd.isoformat(),
                        "epoch": dt_u_upd.timestamp(),
                        "category": "network",
                        "source": "WHOIS / RDAP Registrar",
                        "event_type": "URL_DOMAIN_UPDATED",
                        "title": f"Discovered Domain Renewed: {dom}",
                        "description": f"Registrar record last updated.",
                        "severity": "info",
                        "is_anomaly": False
                    })

        # 8. Primary Domain / IP Target WHOIS Dates (for domain jobs)
        dom_data = getattr(job, "domain_info", None)
        if dom_data and isinstance(dom_data, dict):
            whois_info = dom_data.get("whois_info") or dom_data.get("whois") or {}
            target_name = dom_data.get("target") or getattr(job, "filename", "Target")

            # Domain Creation / Registration
            reg_date = whois_info.get("creation_date") or whois_info.get("created") or whois_info.get("registration_date")
            dt_reg = cls._parse_timestamp(reg_date)
            if dt_reg:
                events.append({
                    "timestamp": dt_reg.isoformat(),
                    "epoch": dt_reg.timestamp(),
                    "category": "network",
                    "source": "WHOIS Registrar",
                    "event_type": "DOMAIN_REGISTERED",
                    "title": f"Target Domain Registered: {target_name}",
                    "description": f"Domain registered with {whois_info.get('registrar', 'Registrar')}. Age: {dom_data.get('age_days', 'N/A')} days.",
                    "severity": "info",
                    "is_anomaly": False
                })

            # Domain Updated / Renewed
            upd_date = whois_info.get("updated_date") or whois_info.get("updated") or whois_info.get("last_updated")
            dt_upd = cls._parse_timestamp(upd_date)
            if dt_upd:
                events.append({
                    "timestamp": dt_upd.isoformat(),
                    "epoch": dt_upd.timestamp(),
                    "category": "network",
                    "source": "WHOIS Registrar",
                    "event_type": "DOMAIN_UPDATED",
                    "title": f"Domain Renewed / Updated: {target_name}",
                    "description": "Registrar records updated.",
                    "severity": "info",
                    "is_anomaly": False
                })

            # Domain Expiration
            exp_date = whois_info.get("expiration_date") or whois_info.get("expires")
            dt_exp = cls._parse_timestamp(exp_date)
            if dt_exp:
                events.append({
                    "timestamp": dt_exp.isoformat(),
                    "epoch": dt_exp.timestamp(),
                    "category": "network",
                    "source": "WHOIS Registrar",
                    "event_type": "DOMAIN_EXPIRATION",
                    "title": f"Domain Expiration Date: {target_name}",
                    "description": f"Domain registration expiry scheduled for {exp_date}.",
                    "severity": "info",
                    "is_anomaly": False
                })

            # TLS Certificate validity
            tls_data = dom_data.get("tls_info") or {}
            cert_val = tls_data.get("valid_from")
            dt_cert_from = cls._parse_timestamp(cert_val)
            if dt_cert_from:
                events.append({
                    "timestamp": dt_cert_from.isoformat(),
                    "epoch": dt_cert_from.timestamp(),
                    "category": "network",
                    "source": "TLS / SSL Certificate",
                    "event_type": "CERTIFICATE_ISSUED",
                    "title": f"TLS Certificate Issued: {tls_data.get('issuer', 'CA')}",
                    "description": f"Subject: {tls_data.get('subject', target_name)}, Cipher: {tls_data.get('cipher', 'TLS')}.",
                    "severity": "info",
                    "is_anomaly": False
                })

            cert_to = tls_data.get("valid_to")
            dt_cert_to = cls._parse_timestamp(cert_to)
            if dt_cert_to:
                events.append({
                    "timestamp": dt_cert_to.isoformat(),
                    "epoch": dt_cert_to.timestamp(),
                    "category": "network",
                    "source": "TLS / SSL Certificate",
                    "event_type": "CERTIFICATE_EXPIRATION",
                    "title": f"TLS Certificate Expiration: {target_name}",
                    "description": f"Certificate valid until {cert_to}.",
                    "severity": "info",
                    "is_anomaly": False
                })

        # 9. PE / Executable Compilation Timestamp
        bin_data = getattr(job, "binary_info", None)
        dt_pe = None
        if bin_data and isinstance(bin_data, dict):
            file_hdr = bin_data.get("file_header", {})
            pe_ts_str = file_hdr.get("timestamp")
            dt_pe = cls._parse_timestamp(pe_ts_str)
            if dt_pe:
                events.append({
                    "timestamp": dt_pe.isoformat(),
                    "epoch": dt_pe.timestamp(),
                    "category": "binary",
                    "source": "COFF File Header",
                    "event_type": "PE_COMPILATION_TIMESTAMP",
                    "title": f"Binary Compiled: {bin_data.get('compiler') or 'Native Executable'}",
                    "description": f"COFF TimeDateStamp recorded as {pe_ts_str} (Machine: {file_hdr.get('machine', 'x86/x64')}).",
                    "severity": "info",
                    "is_anomaly": False
                })

                # Check if compilation date is in the future
                if created_at_dt and dt_pe > created_at_dt:
                    diff_sec = int((dt_pe - created_at_dt).total_seconds())
                    events.append({
                        "timestamp": dt_pe.isoformat(),
                        "epoch": dt_pe.timestamp(),
                        "category": "anomaly",
                        "source": "Forensic Anomaly Detector",
                        "event_type": "TIMESTOMPING_FUTURE_TIMESTAMP",
                        "title": f"Anti-Forensic Timestomping: Compilation Date in Future ({diff_sec}s into future)",
                        "description": "Binary compile timestamp is newer than current file ingestion time. The TimeDateStamp header was artificially modified by the author (MITRE T1070.006).",
                        "severity": "critical",
                        "is_anomaly": True
                    })

                # Check Delphi Default Timestamp (0x2A25C7B9 = 1992-06-19 22:22:17 UTC)
                raw_tds = file_hdr.get("time_date_stamp_raw") or 0
                if raw_tds == 0x2A25C7B9 or (dt_pe.year == 1992 and dt_pe.month == 6 and dt_pe.day == 19):
                    events.append({
                        "timestamp": dt_pe.isoformat(),
                        "epoch": dt_pe.timestamp(),
                        "category": "anomaly",
                        "source": "Forensic Anomaly Detector",
                        "event_type": "TIMESTOMPING_DELPHI_EPOCH",
                        "title": "Anti-Forensics: Delphi Default Epoch Signature (1992-06-19 22:22:17)",
                        "description": "PE TimeDateStamp exactly matches the Borland Delphi default linker timestamp (0x2A25C7B9), commonly observed in Delphi droppers or timestomped malware stubs.",
                        "severity": "high",
                        "is_anomaly": True
                    })

                # Check Unix Zero Epoch / Null Stamp (0x00000000 = 1970-01-01)
                if raw_tds == 0 or (dt_pe.year == 1970 and dt_pe.month == 1 and dt_pe.day == 1):
                    events.append({
                        "timestamp": dt_pe.isoformat(),
                        "epoch": dt_pe.timestamp(),
                        "category": "anomaly",
                        "source": "Forensic Anomaly Detector",
                        "event_type": "TIMESTOMPING_ZERO_EPOCH",
                        "title": "Anti-Forensics: Zero Epoch Wipe (1970-01-01 00:00:00 UTC)",
                        "description": "PE TimeDateStamp was wiped or zeroed out (0x00000000), deliberately suppressing compilation telemetry to evade chronological correlation.",
                        "severity": "high",
                        "is_anomaly": True
                    })

                # Check Nanosecond Zeroing Indicator
                if pe_ts_str and (".000000" in pe_ts_str or pe_ts_str.endswith(":00.000")):
                    events.append({
                        "timestamp": dt_pe.isoformat(),
                        "epoch": dt_pe.timestamp(),
                        "category": "anomaly",
                        "source": "Forensic Anomaly Detector",
                        "event_type": "TIMESTOMPING_NANOSECOND_ZEROING",
                        "title": "Anti-Forensics: Nanosecond Zeroing Artifact Detected",
                        "description": "Timestamp exhibits sub-second zeroing (.000000), a standard indicator of synthetic file time modification tools such as timestomp.exe or SetFileTime.",
                        "severity": "warning",
                        "is_anomaly": True
                    })

        # 9b. Windows Event Logs (EVTX) Forensic Events & Anti-Forensic Tampering
        evtx_info = getattr(job, "evtx_info", None)
        if not evtx_info and hasattr(job, "analysis_data") and isinstance(getattr(job, "analysis_data"), dict):
            evtx_info = job.analysis_data.get("evtx")

        if evtx_info and isinstance(evtx_info, dict):
            # Read all timeline events, critical events, and structured records
            records = (
                evtx_info.get("timeline")
                or evtx_info.get("timeline_events")
                or evtx_info.get("records")
                or evtx_info.get("events")
                or evtx_info.get("critical_events")
                or []
            )
            if not records:
                threats = evtx_info.get("threats") or {}
                for t_list in threats.values():
                    if isinstance(t_list, list):
                        records.extend(t_list)

            seen_evtx_keys = set()
            for rec in records:
                rec_ts = rec.get("timestamp") or rec.get("time_created") or rec.get("SystemTime")
                dt_rec = cls._parse_timestamp(rec_ts)
                if not dt_rec:
                    continue

                eid = str(rec.get("event_id") or rec.get("EventID") or "")
                provider = rec.get("provider") or rec.get("channel") or "Security"
                comp = rec.get("computer") or getattr(job, "original_filename", None) or "Host"
                user = rec.get("user") or rec.get("TargetUserName") or rec.get("target_user_name") or "-"
                summary = rec.get("summary") or rec.get("event_name") or f"Event {eid}"
                threat_reason = rec.get("threat_reason")
                cmd = rec.get("command_line") or rec.get("decoded_command") or rec.get("script_text")
                is_threat = bool(rec.get("is_threat") or rec.get("threat_reason") or eid in ["1102", "104", "5001", "4616"])

                # Deduplicate by (timestamp, event_id, computer, user)
                dedup_key = f"{dt_rec.isoformat()}_{eid}_{comp}_{user}"
                if dedup_key in seen_evtx_keys:
                    continue
                seen_evtx_keys.add(dedup_key)

                # Check Anti-Forensic Log Clear events (Event 1102 Security, Event 104 System)
                if eid in ["1102", "104"]:
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "anomaly",
                        "source": f"Windows Event Log ({provider})",
                        "event_type": "EVTX_AUDIT_LOG_CLEARED",
                        "title": f"CRITICAL ANOMALY: Windows Event Audit Log Cleared (Event {eid}) [{comp}]",
                        "description": f"The security audit log was cleared on host {comp} by user '{user}'. Direct indicator of anti-forensic evidence wiping (MITRE T1070.001).",
                        "severity": "critical",
                        "is_anomaly": True,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Check System Time Tampering (Event 4616)
                if eid == "4616":
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "anomaly",
                        "source": f"Windows Event Log ({provider})",
                        "event_type": "EVTX_SYSTEM_TIME_CHANGED",
                        "title": f"CRITICAL ANOMALY: System Time Changed (Event 4616) [{comp}]",
                        "description": f"The system time was modified on host {comp} by process or user '{user}'. Potential timestomping or event log manipulation.",
                        "severity": "critical",
                        "is_anomaly": True,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Check Microsoft Defender Real-Time Protection Disabled (Event 5001)
                if eid == "5001":
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "anomaly",
                        "source": f"Windows Defender ({provider})",
                        "event_type": "EVTX_DEFENDER_DISABLED",
                        "title": f"CRITICAL ANOMALY: Defender Real-Time Protection Disabled [{comp}]",
                        "description": f"Antivirus real-time monitoring disabled on host {comp} by user '{user}'.",
                        "severity": "critical",
                        "is_anomaly": True,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Process Creation (Event 4688 or Sysmon Event 1)
                if eid in ["4688", "1"]:
                    proc_name = str(rec.get("process_name") or rec.get("new_process_name") or rec.get("CommandLine") or rec.get("Image") or "Process")
                    parent = str(rec.get("parent_process") or rec.get("parent_process_name") or rec.get("ParentImage") or "Parent")
                    proc_base = proc_name.replace("/", "\\").split("\\")[-1]
                    parent_base = parent.replace("/", "\\").split("\\")[-1]
                    is_susp_proc = is_threat or "powershell" in proc_name.lower() or "cmd" in proc_name.lower() or "vssadmin" in str(cmd).lower()
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "anomaly" if is_susp_proc else "evtx",
                        "source": f"EVTX Process Tracking ({provider})",
                        "event_type": "EVTX_PROCESS_CREATION",
                        "title": f"Process Created: {proc_base} (PID {rec.get('process_id', 'N/A')}) [{comp}]",
                        "description": f"Host: {comp}, User: {user}, Parent: {parent_base}. {f'Threat: {threat_reason}. ' if threat_reason else ''}CLI: {cmd or rec.get('command_line', 'N/A')}",
                        "severity": "high" if is_susp_proc else "info",
                        "is_anomaly": is_susp_proc,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # User Logon (Event 4624 / 4625)
                if eid in ["4624", "4625"]:
                    is_failed = eid == "4625"
                    logon_type = rec.get("logon_type", "Logon")
                    src_ip = rec.get("ip_address") or rec.get("ip") or "local"
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Authentication ({provider})",
                        "event_type": "EVTX_USER_LOGON",
                        "title": f"Logon {'FAILED' if is_failed else 'SUCCESS'}: {user} ({logon_type}) [{comp}]",
                        "description": f"Host: {comp}, Source IP: {src_ip}, Workstation: {rec.get('workstation', comp)}, User: {user}",
                        "severity": "warning" if is_failed else "info",
                        "is_anomaly": is_failed and (is_threat or rec.get("severity") in ["high", "critical"]),
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Service Installed (Event 7045 / 4697)
                if eid in ["7045", "4697"]:
                    svc_name = rec.get("service_name") or rec.get("ServiceName") or "Service"
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Service Control ({provider})",
                        "event_type": "EVTX_SERVICE_INSTALLED",
                        "title": f"New Service Installed: {svc_name} [{comp}]",
                        "description": f"Service '{svc_name}' registered on {comp}. Image Path: {rec.get('image_path') or rec.get('details', {}).get('ImagePath') or 'N/A'}",
                        "severity": "high" if is_threat else "warning",
                        "is_anomaly": is_threat,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Scheduled Tasks (Event 4698 / 4699 / 4702)
                if eid in ["4698", "4699", "4702"]:
                    task_name = rec.get("task_name") or rec.get("TaskName") or "Task"
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Task Scheduler ({provider})",
                        "event_type": "EVTX_SCHEDULED_TASK",
                        "title": f"Scheduled Task ({eid}): {task_name} [{comp}]",
                        "description": f"Scheduled task '{task_name}' on {comp}. User: {user}.",
                        "severity": "high" if eid == "4698" else "info",
                        "is_anomaly": is_threat,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Lateral Movement / Network Share Access (Event 5140 / 5145)
                if eid in ["5140", "5145"]:
                    share = rec.get("share_name") or rec.get("details", {}).get("ShareName") or "Share"
                    tgt = rec.get("relative_target_name") or rec.get("details", {}).get("RelativeTargetName") or ""
                    tgt_clean = f"\\{tgt}" if tgt and tgt != "\\" else ""
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Share Access ({provider})",
                        "event_type": "EVTX_SHARE_ACCESS",
                        "title": f"Network Share Access: {share}{tgt_clean} [{comp}]",
                        "description": f"Host: {comp}, User: {user}, IP: {rec.get('ip_address', 'local')}. Access to {share}{tgt_clean}. {threat_reason or ''}",
                        "severity": "critical" if (is_threat and rec.get("severity") == "critical") else ("high" if is_threat else "info"),
                        "is_anomaly": is_threat,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # PowerShell Script Block (Event 4104)
                if eid == "4104":
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX PowerShell ({provider})",
                        "event_type": "EVTX_POWERSHELL_SCRIPT",
                        "title": f"PowerShell Script Block Logging (Event 4104) [{comp}]",
                        "description": f"Host: {comp}, User: {user}. {(cmd or rec.get('summary') or '')[:140]}",
                        "severity": "high" if is_threat else "medium",
                        "is_anomaly": is_threat,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Print Spooler (Event 307)
                if eid == "307":
                    doc = rec.get("details", {}).get("Param1") or rec.get("document_name") or "Document"
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Print Spooler ({provider})",
                        "event_type": "EVTX_PRINT_JOB",
                        "title": f"Print Spooler Job: {doc} [{comp}]",
                        "description": f"Document '{doc}' sent to printer by {user} on {comp}.",
                        "severity": "high" if is_threat else "info",
                        "is_anomaly": is_threat,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Plugged-in Hardware & USB (Events 6416, 2003, 2100, etc.)
                if eid in ["6416", "2003", "2100", "2101", "2102", "1003", "1004", "20001", "20003"]:
                    dname = rec.get("details", {}).get("DeviceDescription") or rec.get("device_name") or "External Storage Device"
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Hardware / USB ({provider})",
                        "event_type": "EVTX_USB_HARDWARE",
                        "title": f"External Hardware Connected: {dname} [{comp}]",
                        "description": f"Hardware device '{dname}' connected on {comp} by {user}.",
                        "severity": "medium",
                        "is_anomaly": False,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # Privilege Escalation / Group Manipulation (Events 4672, 4728, 4732, 4756)
                if eid in ["4672", "4728", "4732", "4756"]:
                    events.append({
                        "timestamp": dt_rec.isoformat(),
                        "epoch": dt_rec.timestamp(),
                        "category": "evtx",
                        "source": f"EVTX Privilege Tracking ({provider})",
                        "event_type": "EVTX_PRIVILEGE_ESCALATION",
                        "title": f"Privilege Change / Admin Group Addition (Event {eid}) [{comp}]",
                        "description": f"Host: {comp}, User: {user}. {summary}. {threat_reason or ''}",
                        "severity": "high",
                        "is_anomaly": True,
                        "computer": comp,
                        "user": user,
                        "event_id": eid,
                    })
                    continue

                # General EVTX event
                events.append({
                    "timestamp": dt_rec.isoformat(),
                    "epoch": dt_rec.timestamp(),
                    "category": "anomaly" if is_threat else "evtx",
                    "source": f"Windows Event Log ({provider})",
                    "event_type": f"EVTX_EVENT_{eid}",
                    "title": f"{summary} (Event {eid}) [{comp}]",
                    "description": rec.get("message") or rec.get("description") or f"Event {eid} ({provider}) recorded on host {comp} for user '{user}'.",
                    "severity": rec.get("severity") or ("high" if is_threat else "info"),
                    "is_anomaly": is_threat,
                    "computer": comp,
                    "user": user,
                    "event_id": eid,
                })

        # 9c. Network Packet Capture (PCAP) Traffic Timestamps
        pcap_info = getattr(job, "pcap_info", None)
        if not pcap_info and hasattr(job, "analysis_data") and isinstance(getattr(job, "analysis_data"), dict):
            pcap_info = job.analysis_data.get("pcap")

        if pcap_info and isinstance(pcap_info, dict):
            start_ts = pcap_info.get("start_time") or pcap_info.get("first_packet_time")
            dt_pcap_start = cls._parse_timestamp(start_ts)
            if dt_pcap_start:
                events.append({
                    "timestamp": dt_pcap_start.isoformat(),
                    "epoch": dt_pcap_start.timestamp(),
                    "category": "network",
                    "source": "PCAP Network Capture",
                    "event_type": "PCAP_CAPTURE_START",
                    "title": f"Network Traffic Capture Start ({getattr(job, 'filename', 'traffic.pcap')})",
                    "description": f"First packet received. Packets: {pcap_info.get('packet_count', 0)}, Protocols: {', '.join(pcap_info.get('protocols', []))}",
                    "severity": "info",
                    "is_anomaly": False
                })

            end_ts = pcap_info.get("end_time") or pcap_info.get("last_packet_time")
            dt_pcap_end = cls._parse_timestamp(end_ts)
            if dt_pcap_end:
                events.append({
                    "timestamp": dt_pcap_end.isoformat(),
                    "epoch": dt_pcap_end.timestamp(),
                    "category": "network",
                    "source": "PCAP Network Capture",
                    "event_type": "PCAP_CAPTURE_END",
                    "title": "Network Traffic Capture End",
                    "description": f"Capture session terminated. Total duration: {pcap_info.get('duration_seconds', 0)} seconds.",
                    "severity": "info",
                    "is_anomaly": False
                })

            # DNS Queries
            for dq in (pcap_info.get("dns_queries") or []):
                dt_dq = cls._parse_timestamp(dq.get("timestamp"))
                if dt_dq:
                    events.append({
                        "timestamp": dt_dq.isoformat(),
                        "epoch": dt_dq.timestamp(),
                        "category": "network",
                        "source": "PCAP DNS Resolution",
                        "event_type": "PCAP_DNS_QUERY",
                        "title": f"DNS Query: {dq.get('query', 'domain')}",
                        "description": f"Client {dq.get('client_ip', 'client')} queried {dq.get('query')}. Resolved IP: {dq.get('resolved_ip', 'N/A')}",
                        "severity": "info",
                        "is_anomaly": False
                    })

            # HTTP Transactions
            for http in (pcap_info.get("http_transactions") or []):
                dt_http = cls._parse_timestamp(http.get("timestamp"))
                if dt_http:
                    m = http.get("method", "HTTP")
                    h = http.get("host") or http.get("server_ip") or "server"
                    u = http.get("uri") or "/"
                    code = http.get("response_code") or ""
                    is_post = m.upper() == "POST"
                    is_exfil = is_post or bool(http.get("is_exfiltration")) or int(http.get("bytes_out", 0)) > 100000
                    events.append({
                        "timestamp": dt_http.isoformat(),
                        "epoch": dt_http.timestamp(),
                        "category": "network",
                        "source": "PCAP HTTP Transaction",
                        "event_type": "PCAP_HTTP_TRANSACTION",
                        "title": f"HTTP {m} {h}{u[:30]} ({code or 'REQ'})",
                        "description": f"Client {http.get('client_ip', 'client')} -> {h}:{http.get('port', 80)}{u}. Status: {code}. Bytes: {http.get('bytes_out', 0)} sent, {http.get('bytes_in', 0)} rcvd.",
                        "severity": "high" if is_exfil else "info",
                        "is_anomaly": is_exfil
                    })

            # Captured Plaintext Credentials
            for cred in (pcap_info.get("credentials") or []):
                dt_cred = cls._parse_timestamp(cred.get("timestamp"))
                if dt_cred:
                    proto = cred.get("protocol", "AUTH")
                    usr = cred.get("username") or "user"
                    events.append({
                        "timestamp": dt_cred.isoformat(),
                        "epoch": dt_cred.timestamp(),
                        "category": "anomaly",
                        "source": f"PCAP Credential Interceptor ({proto})",
                        "event_type": "PCAP_CREDENTIAL_CAPTURED",
                        "title": f"CRITICAL: Plaintext Credential Captured: '{usr}' via {proto}",
                        "description": f"Cleartext authentication overheard from {cred.get('client_ip', 'client')} targeting {cred.get('server_ip', 'server')}.",
                        "severity": "critical",
                        "is_anomaly": True
                    })

            # Carved and Transferred Files
            for tf in (pcap_info.get("transferred_files") or []):
                dt_tf = cls._parse_timestamp(tf.get("timestamp"))
                if dt_tf:
                    fname = tf.get("filename") or "payload.bin"
                    is_danger = any(fname.lower().endswith(ext) for ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".bin"])
                    events.append({
                        "timestamp": dt_tf.isoformat(),
                        "epoch": dt_tf.timestamp(),
                        "category": "anomaly" if is_danger else "network",
                        "source": "PCAP Transferred File",
                        "event_type": "PCAP_TRANSFERRED_FILE",
                        "title": f"{'MALICIOUS PAYLOAD' if is_danger else 'File'} Transferred: {fname}",
                        "description": f"Transfer of '{fname}' ({tf.get('size_bytes', 0)} bytes) from {tf.get('source_ip', 'client')} to {tf.get('destination_ip', 'server')} via {tf.get('protocol', 'TCP')}.",
                        "severity": "critical" if is_danger else "info",
                        "is_anomaly": is_danger
                    })

            # Web Searches
            for sq in (pcap_info.get("search_queries") or []):
                dt_sq = cls._parse_timestamp(sq.get("timestamp"))
                if dt_sq:
                    events.append({
                        "timestamp": dt_sq.isoformat(),
                        "epoch": dt_sq.timestamp(),
                        "category": "network",
                        "source": "PCAP Web Search Inspector",
                        "event_type": "PCAP_WEB_SEARCH",
                        "title": f"Web Search: '{sq.get('query')}' ({sq.get('engine', 'Search')})",
                        "description": f"User on {sq.get('client_ip', 'endpoint')} searched for '{sq.get('query')}' on {sq.get('engine')}.",
                        "severity": "info",
                        "is_anomaly": False
                    })

            # Terminal Shell Sessions
            for ts in (pcap_info.get("terminal_sessions") or []):
                dt_term = cls._parse_timestamp(ts.get("timestamp"))
                if dt_term:
                    events.append({
                        "timestamp": dt_term.isoformat(),
                        "epoch": dt_term.timestamp(),
                        "category": "anomaly",
                        "source": f"PCAP Terminal Interceptor ({ts.get('protocol', 'TELNET')})",
                        "event_type": "PCAP_TERMINAL_COMMAND",
                        "title": f"Interactive Terminal Command: {ts.get('command') or 'Shell'}",
                        "description": f"Interactive command captured on {ts.get('server_ip', 'server')}: {ts.get('command')}",
                        "severity": "high",
                        "is_anomaly": True
                    })

            # Intercepted Emails
            for em in (pcap_info.get("emails") or []):
                dt_em = cls._parse_timestamp(em.get("timestamp"))
                if dt_em:
                    events.append({
                        "timestamp": dt_em.isoformat(),
                        "epoch": dt_em.timestamp(),
                        "category": "email",
                        "source": "PCAP SMTP Email Interceptor",
                        "event_type": "PCAP_INTERCEPTED_EMAIL",
                        "title": f"Intercepted Email: {em.get('subject', 'No Subject')}",
                        "description": f"From: {em.get('from', 'Sender')} To: {em.get('to', 'Recipient')} Subject: '{em.get('subject', '')}'. Attachments: {len(em.get('attachments', []))}.",
                        "severity": "info",
                        "is_anomaly": False
                    })

            # Beaconing C2 Flows
            for bf in (pcap_info.get("beaconing_flows") or []):
                dt_bf = cls._parse_timestamp(bf.get("timestamp"))
                if dt_bf:
                    events.append({
                        "timestamp": dt_bf.isoformat(),
                        "epoch": dt_bf.timestamp(),
                        "category": "anomaly",
                        "source": "PCAP C2 Beaconing Detector",
                        "event_type": "PCAP_BEACONING_FLOW",
                        "title": f"Command & Control Beaconing Pattern: {bf.get('destination_ip', 'C2')}",
                        "description": f"Periodic traffic detected to {bf.get('destination_ip')}:{bf.get('port', '')}. Interval: ~{bf.get('interval_seconds', 0)}s, Score: {bf.get('beaconing_score', 0)}/100.",
                        "severity": "critical",
                        "is_anomaly": True
                    })

        # 9d. Windows Shortcut (LNK) Target & Creation Timestamps
        lnk_info = getattr(job, "lnk_info", None)
        if not lnk_info and hasattr(job, "analysis_data") and isinstance(getattr(job, "analysis_data"), dict):
            lnk_info = job.analysis_data.get("lnk")

        if lnk_info and isinstance(lnk_info, dict):
            lnk_created = lnk_info.get("creation_time") or lnk_info.get("created")
            dt_lnk_c = cls._parse_timestamp(lnk_created)
            if dt_lnk_c:
                events.append({
                    "timestamp": dt_lnk_c.isoformat(),
                    "epoch": dt_lnk_c.timestamp(),
                    "category": "filesystem",
                    "source": "LNK Shell Link",
                    "event_type": "LNK_FILE_CREATED",
                    "title": f"Shortcut LNK Created: {getattr(job, 'filename', 'shortcut.lnk')}",
                    "description": f"Target path: {lnk_info.get('target_path', 'unknown')}, Target size: {lnk_info.get('target_size', 0)} bytes.",
                    "severity": "info",
                    "is_anomaly": False
                })

            tgt_mod = lnk_info.get("target_modification_time") or lnk_info.get("target_mtime")
            dt_tgt_m = cls._parse_timestamp(tgt_mod)
            if dt_tgt_m:
                events.append({
                    "timestamp": dt_tgt_m.isoformat(),
                    "epoch": dt_tgt_m.timestamp(),
                    "category": "filesystem",
                    "source": "LNK Shell Link Target",
                    "event_type": "LNK_TARGET_MODIFIED",
                    "title": f"LNK Target File Last Modified: {lnk_info.get('target_path', 'target')}",
                    "description": f"Target file modification recorded inside LNK header.",
                    "severity": "info",
                    "is_anomaly": False
                })

        # 10. Threat Intelligence Timestamps (VirusTotal, CrowdStrike / Hybrid Analysis, MalwareBazaar, ThreatFox, OTX)
        vt_data = getattr(job, "virustotal", None)
        if vt_data and isinstance(vt_data, dict):
            first_sub = vt_data.get("first_submission_date")
            dt_fs = cls._parse_timestamp(first_sub)
            if dt_fs:
                events.append({
                    "timestamp": dt_fs.isoformat(),
                    "epoch": dt_fs.timestamp(),
                    "category": "threat_intel",
                    "source": "VirusTotal Intelligence",
                    "event_type": "VT_FIRST_SEEN",
                    "title": "VirusTotal First Submission Date",
                    "description": f"Sample was first submitted to VirusTotal. Detections: {vt_data.get('positives', 0)}/{vt_data.get('total_engines', 0)} engines.",
                    "severity": "high" if vt_data.get("positives", 0) > 0 else "info",
                    "is_anomaly": False
                })

            last_sub = vt_data.get("last_analysis_date") or vt_data.get("last_modification_date")
            dt_ls = cls._parse_timestamp(last_sub)
            if dt_ls:
                events.append({
                    "timestamp": dt_ls.isoformat(),
                    "epoch": dt_ls.timestamp(),
                    "category": "threat_intel",
                    "source": "VirusTotal Intelligence",
                    "event_type": "VT_LAST_ANALYSIS",
                    "title": "VirusTotal Most Recent Engine Scan",
                    "description": f"Latest VirusTotal multi-engine scanning pass completed at {last_sub}.",
                    "severity": "info",
                    "is_anomaly": False
                })

        ha_data = getattr(job, "hybrid_analysis", None)
        if ha_data and isinstance(ha_data, dict):
            ha_ts = ha_data.get("start_time") or ha_data.get("analysis_start_time") or ha_data.get("created_at")
            dt_ha = cls._parse_timestamp(ha_ts)
            if dt_ha:
                events.append({
                    "timestamp": dt_ha.isoformat(),
                    "epoch": dt_ha.timestamp(),
                    "category": "threat_intel",
                    "source": "CrowdStrike Falcon / Hybrid Analysis",
                    "event_type": "CROWDSTRIKE_HYBRID_ANALYSIS",
                    "title": f"CrowdStrike Falcon Sandbox: {ha_data.get('verdict', 'Analysis').upper()}",
                    "description": f"Threat score: {ha_data.get('threat_score', 0)}/100, Malware family: {ha_data.get('malware_family') or 'N/A'}. Environment: {ha_data.get('environment') or 'Sandbox'}.",
                    "severity": "critical" if ha_data.get("threat_score", 0) >= 70 else ("warning" if ha_data.get("threat_score", 0) >= 40 else "info"),
                    "is_anomaly": False
                })

        mb_data = getattr(job, "malwarebazaar", None)
        if mb_data and isinstance(mb_data, dict):
            mb_ts = mb_data.get("first_seen")
            dt_mb = cls._parse_timestamp(mb_ts)
            if dt_mb:
                events.append({
                    "timestamp": dt_mb.isoformat(),
                    "epoch": dt_mb.timestamp(),
                    "category": "threat_intel",
                    "source": "MalwareBazaar",
                    "event_type": "MALWAREBAZAAR_FIRST_SEEN",
                    "title": f"MalwareBazaar IOC Ingest: {mb_data.get('signature', 'Malware')}",
                    "description": f"Uploaded by reporter '{mb_data.get('reporter', 'community')}' with tags {', '.join(mb_data.get('tags', []))}.",
                    "severity": "critical",
                    "is_anomaly": False
                })

        tf_data = getattr(job, "threatfox", None)
        if tf_data and isinstance(tf_data, dict):
            tf_ts = tf_data.get("first_seen_utc") or tf_data.get("first_seen")
            dt_tf = cls._parse_timestamp(tf_ts)
            if dt_tf:
                events.append({
                    "timestamp": dt_tf.isoformat(),
                    "epoch": dt_tf.timestamp(),
                    "category": "threat_intel",
                    "source": "ThreatFox IOC",
                    "event_type": "THREATFOX_FIRST_SEEN",
                    "title": f"ThreatFox Threat Activity: {tf_data.get('malware', 'Threat')}",
                    "description": f"Active {tf_data.get('threat_type', 'threat')} indicator indexed with confidence {tf_data.get('confidence', 0)}%.",
                    "severity": "critical",
                    "is_anomaly": False
                })

        otx_data = getattr(job, "alienvault_otx", None)
        if otx_data and isinstance(otx_data, dict):
            pulse_dates = otx_data.get("pulse_dates", [])
            for p_date in pulse_dates[:5]:
                dt_otx = cls._parse_timestamp(p_date)
                if dt_otx:
                    events.append({
                        "timestamp": dt_otx.isoformat(),
                        "epoch": dt_otx.timestamp(),
                        "category": "threat_intel",
                        "source": "AlienVault OTX",
                        "event_type": "OTX_PULSE_REPORTED",
                        "title": "AlienVault OTX Pulse Published",
                        "description": f"Indicator flagged across {otx_data.get('pulse_count', 0)} threat exchange pulses. Tags: {', '.join(otx_data.get('tags', []))}",
                        "severity": "high",
                        "is_anomaly": False
                    })

        # 11. Security & Threat Detection Findings (Timestomping, YARA, Deobfuscation)
        findings = getattr(job, "findings", [])
        if findings:
            for f in findings:
                f_dict = f.model_dump() if hasattr(f, "model_dump") else (f if isinstance(f, dict) else {})
                title = f_dict.get("title", "")
                if "timestomp" in title.lower() or "timestamp" in title.lower() or "clock" in title.lower():
                    # Place anomaly near current time or document time
                    ts_anomaly = created_at_dt.isoformat() if created_at_dt else datetime.now(timezone.utc).isoformat()
                    events.append({
                        "timestamp": ts_anomaly,
                        "epoch": created_at_dt.timestamp() if created_at_dt else datetime.now(timezone.utc).timestamp(),
                        "category": "anomaly",
                        "source": "Security Engine",
                        "event_type": "TIMESTOMPING_FINDING",
                        "title": title,
                        "description": f_dict.get("description", ""),
                        "severity": f_dict.get("severity", "critical"),
                        "is_anomaly": True
                    })

        # Chronologically sort all events by epoch
        events.sort(key=lambda x: x["epoch"])

        # Enrich each event with ID, job_id, filename, artifact_type, and kill_chain_phase
        job_id = getattr(job, "job_id", "")
        job_fn = getattr(job, "filename", "") or getattr(job, "original_filename", "")
        default_cat = getattr(job, "category", "")

        for idx, e in enumerate(events):
            if not e.get("id"):
                raw_key = f"{e.get('timestamp')}_{e.get('title')}_{e.get('event_type')}_{idx}"
                e["id"] = f"evt_{abs(hash(raw_key)) % 10000000:07d}"
            if not e.get("job_id") and job_id:
                e["job_id"] = job_id
            if not e.get("filename") and job_fn:
                e["filename"] = job_fn
            if not e.get("artifact_type"):
                e["artifact_type"] = cls._classify_artifact_type(e, default_cat)
            if not e.get("kill_chain_phase"):
                e["kill_chain_phase"] = cls._classify_kill_chain_phase(e)

        return events

    @staticmethod
    def _classify_kill_chain_phase(event: Dict[str, Any]) -> str:
        et = str(event.get("event_type", "")).upper()
        title = str(event.get("title", "")).lower()
        desc = str(event.get("description", "")).lower()
        cat = str(event.get("category", "")).lower()

        # 1. Defense Evasion & Anti-Forensics
        if any(x in et for x in ["TIMESTOMP", "AUDIT_LOG_CLEARED", "SYSTEM_TIME_CHANGED", "1102", "104", "4616"]):
            return "defense_evasion"
        if any(w in title or w in desc for w in ["timestomp", "audit log cleared", "cleared audit", "time changed", "anti-debug", "amsi bypass", "tamper", "evasion", "hide", "obfusc"]):
            return "defense_evasion"

        # 2. Command and Control (C2)
        if any(x in et for x in ["PCAP_DNS", "PCAP_CAPTURE", "BEACON", "DNS_QUERY", "C2"]):
            return "command_and_control"
        if any(w in title or w in desc for w in ["beacon", "c2", "dns query", "external ip", "traffic"]):
            return "command_and_control"

        # 3. Persistence
        if any(x in et for x in ["SERVICE_INSTALLED", "SCHEDULED_TASK", "7045", "4698"]):
            return "persistence"
        if any(w in title or w in desc for w in ["service installed", "scheduled task", "run key", "startup"]):
            return "persistence"

        # 4. Privilege Escalation
        if "4624" in et and any(w in desc for w in ["system", "elevat", "admin"]):
            return "privilege_escalation"
        if any(w in title or w in desc for w in ["privilege escalation", "uac bypass", "token impersonation"]):
            return "privilege_escalation"

        # 5. Credential Access
        if any(w in title or w in desc for w in ["credential", "lsass", "mimikatz", "brute force", "passwords", "4625"]):
            return "credential_access"

        # 6. Lateral Movement
        if any(w in title or w in desc for w in ["lateral", "psexec", "smb share", "rdp connection"]):
            return "lateral_movement"

        # 7. Initial Access
        if any(x in et for x in ["EMAIL_ORIGIN", "EMAIL_TRANSIT", "ATTACHMENT", "FILE_INGESTED", "URL_DOMAIN", "DOMAIN_REG"]):
            return "initial_access"
        if any(w in title or w in desc for w in ["phishing", "attachment", "submitted for analysis", "email sent", "inbox"]):
            return "initial_access"

        # 8. Execution
        if any(x in et for x in ["PROCESS_CREATION", "4688", "OFFICE_DOCUMENT", "PDF_DOCUMENT", "LNK_TARGET", "OPENACTION", "POWERSHELL"]):
            return "execution"
        if any(w in title or w in desc for w in ["process spawn", "powershell", "cmd.exe", "wscript", "cscript", "macro run", "launch action"]):
            return "execution"

        # 9. Threat Intelligence
        if any(x in et for x in ["VT_", "CROWDSTRIKE", "MALWAREBAZAAR", "THREATFOX", "OTX", "PREVIOUS_SUBMISSION"]):
            return "threat_intel"

        # 10. Discovery / Artifact Creation
        if any(x in et for x in ["PHOTO_CAPTURED", "FILE_CREATED", "FILE_MODIFIED", "ARCHIVE_MEMBER", "PE_COMPILATION"]):
            return "discovery"

        return "execution" if cat in ["binary", "script", "executable"] else "initial_access"

    @staticmethod
    def _classify_artifact_type(event: Dict[str, Any], default_category: str = "") -> str:
        et = str(event.get("event_type", "")).upper()
        src = str(event.get("source", "")).lower()
        title = str(event.get("title", "")).lower()
        cat = str(event.get("category", "")).lower()

        if "evtx" in et or "evtx" in src or "windows event" in src:
            return "evtx"
        if "pcap" in et or "pcap" in src or "network" in src or "dns" in et:
            return "pcap"
        if "email" in et or "email" in src or "mail" in src or "attachment" in et:
            return "email"
        if "office" in et or "docm" in title or "docx" in title or "excel" in title:
            return "office"
        if "pdf" in et or "pdf" in title:
            return "pdf"
        if "pe_" in et or "binary" in cat or ".exe" in title or ".dll" in title:
            return "binary"
        if "script" in cat or ".ps1" in title or ".vbs" in title or ".bat" in title:
            return "script"
        if "lnk" in et or "lnk" in title or "lnk" in src:
            return "lnk"
        if any(x in et for x in ["VT_", "CROWDSTRIKE", "MALWAREBAZAAR", "THREATFOX", "OTX"]):
            return "threat_intel"
        return default_category or "filesystem"

    @classmethod
    def build_causality_and_swimlanes(cls, events: List[Dict[str, Any]], jobs: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Synthesizes artifact swimlanes and directed cross-artifact causality links
        mapping chronological progression across the attack kill chain.
        """
        sorted_events = sorted(events, key=lambda x: x.get("epoch", 0))

        distinct_files = list(dict.fromkeys(
            e.get("filename") for e in sorted_events if e.get("filename")
        ))
        is_multi_file = len(distinct_files) > 1

        # 1. Build Swimlanes
        swimlanes_map: Dict[str, Dict[str, Any]] = {}
        if is_multi_file:
            for f in distinct_files:
                sample_events = [e for e in sorted_events if e.get("filename") == f]
                sample_art_type = sample_events[0].get("artifact_type", "filesystem") if sample_events else "filesystem"
                swimlanes_map[f] = {
                    "id": f,
                    "title": f,
                    "artifact_type": sample_art_type,
                    "event_count": len(sample_events)
                }
            for e in sorted_events:
                fn = e.get("filename") or distinct_files[0]
                e["swimlane_id"] = fn
        else:
            lane_configs = [
                ("delivery", "Initial Ingestion & Delivery", "email", ["initial_access"]),
                ("execution", "Host Execution & Processes", "binary", ["execution"]),
                ("persistence", "Persistence & Privileges", "system", ["persistence", "privilege_escalation"]),
                ("network", "Network Communications (C2)", "pcap", ["command_and_control"]),
                ("defense_evasion", "Anti-Forensics & Tampering", "anomaly", ["defense_evasion"]),
                ("threat_intel", "Threat Intelligence History", "threat_intel", ["threat_intel", "discovery"])
            ]
            for lid, ltitle, ltype, _ in lane_configs:
                swimlanes_map[lid] = {
                    "id": lid,
                    "title": ltitle,
                    "artifact_type": ltype,
                    "event_count": 0
                }
            for e in sorted_events:
                phase = e.get("kill_chain_phase", "initial_access")
                matched_lid = "execution"
                for lid, _, _, phases in lane_configs:
                    if phase in phases:
                        matched_lid = lid
                        break
                e["swimlane_id"] = matched_lid
                swimlanes_map[matched_lid]["event_count"] += 1

            swimlanes_map = {k: v for k, v in swimlanes_map.items() if v["event_count"] > 0}

        swimlanes = list(swimlanes_map.values())

        # 2. Synthesize Directed Causality Links
        causality_links: List[Dict[str, Any]] = []
        link_id_counter = 1

        phase_map: Dict[str, List[Dict[str, Any]]] = {}
        for e in sorted_events:
            p = e.get("kill_chain_phase", "unknown")
            phase_map.setdefault(p, []).append(e)

        # Rule A: Initial Access -> First Execution
        initial_events = phase_map.get("initial_access", [])
        exec_events = phase_map.get("execution", [])
        if initial_events and exec_events:
            src = initial_events[0]
            dst = exec_events[0]
            if src.get("id") != dst.get("id"):
                causality_links.append({
                    "id": f"link_{link_id_counter}",
                    "source_id": src["id"],
                    "target_id": dst["id"],
                    "label": "Payload Delivered & Executed",
                    "confidence": "HIGH",
                    "description": f"{src.get('title')} delivered payload triggering {dst.get('title')}"
                })
                link_id_counter += 1

        # Rule B: Execution -> Persistence
        persist_events = phase_map.get("persistence", [])
        if exec_events and persist_events:
            src = exec_events[-1]
            dst = persist_events[0]
            if src.get("id") != dst.get("id"):
                causality_links.append({
                    "id": f"link_{link_id_counter}",
                    "source_id": src["id"],
                    "target_id": dst["id"],
                    "label": "Installed Persistence Mechanism",
                    "confidence": "HIGH",
                    "description": f"Process execution established persistence ({dst.get('title')})"
                })
                link_id_counter += 1

        # Rule C: Execution / Persistence -> Command & Control
        c2_events = phase_map.get("command_and_control", [])
        if c2_events:
            src = exec_events[0] if exec_events else (initial_events[0] if initial_events else None)
            dst = c2_events[0]
            if src and src.get("id") != dst.get("id"):
                causality_links.append({
                    "id": f"link_{link_id_counter}",
                    "source_id": src["id"],
                    "target_id": dst["id"],
                    "label": "Initiated C2 Network Traffic",
                    "confidence": "HIGH",
                    "description": f"Payload execution initiated communications to external command & control: {dst.get('title')}"
                })
                link_id_counter += 1

        # Rule D: Activity -> Defense Evasion
        evasion_events = phase_map.get("defense_evasion", [])
        if evasion_events:
            prev_events = c2_events or persist_events or exec_events
            src = prev_events[-1] if prev_events else None
            for dst in evasion_events[:2]:
                if src and src.get("id") != dst.get("id") and not any(l["target_id"] == dst["id"] for l in causality_links):
                    causality_links.append({
                        "id": f"link_{link_id_counter}",
                        "source_id": src["id"],
                        "target_id": dst["id"],
                        "label": "Covered Tracks / Anti-Forensics",
                        "confidence": "HIGH",
                        "description": f"Following malicious activity, anti-forensics / tampering was executed: {dst.get('title')}"
                    })
                    link_id_counter += 1

        # Rule E: Multi-sample cross-artifact links
        if is_multi_file:
            for i in range(len(distinct_files) - 1):
                f_a = distinct_files[i]
                f_b = distinct_files[i + 1]
                events_a = [e for e in sorted_events if e.get("filename") == f_a]
                events_b = [e for e in sorted_events if e.get("filename") == f_b]
                if events_a and events_b:
                    src = events_a[-1]
                    dst = events_b[0]
                    if not any(l["source_id"] == src["id"] and l["target_id"] == dst["id"] for l in causality_links):
                        causality_links.append({
                            "id": f"link_{link_id_counter}",
                            "source_id": src["id"],
                            "target_id": dst["id"],
                            "label": "Correlated Artifact Transition",
                            "confidence": "HIGH",
                            "description": f"Investigation progression from {f_a} to {f_b}"
                        })
                        link_id_counter += 1

        # Rule F: Timestomping Inversion discrepancy
        anomalies = [e for e in sorted_events if e.get("is_anomaly")]
        for a in anomalies:
            legit = [e for e in sorted_events if not e.get("is_anomaly")]
            if legit and not any(l["target_id"] == a["id"] for l in causality_links):
                closest = min(legit, key=lambda x: abs(x.get("epoch", 0) - a.get("epoch", 0)))
                causality_links.append({
                    "id": f"link_{link_id_counter}",
                    "source_id": closest["id"],
                    "target_id": a["id"],
                    "label": "Temporal Discrepancy",
                    "confidence": "HIGH",
                    "description": f"Timestomping anomaly detected relative to authentic timestamp in {closest.get('title')}"
                })
                link_id_counter += 1

        return {
            "swimlanes": swimlanes,
            "causality_links": causality_links
        }

    @classmethod
    def generate_super_timeline(cls, jobs: List[Any]) -> Dict[str, Any]:
        """
        Assembles a master Unified Super-Timeline correlating all chronological events
        across multiple jobs or artifacts in a workspace, cross-checking for temporal
        anomalies and timestomping across files.
        """
        all_events: List[Dict[str, Any]] = []
        seen_keys = set()

        for j in jobs:
            j_events = cls.generate_timeline(j)
            for e in j_events:
                # Deduplicate identical events by timestamp + title + source
                k = (e.get("timestamp"), e.get("title"), e.get("source"))
                if k not in seen_keys:
                    seen_keys.add(k)
                    fname = getattr(j, "filename", "") or getattr(j, "original_filename", "")
                    if fname and not e.get("filename"):
                        e["filename"] = fname
                    all_events.append(e)

        all_events.sort(key=lambda x: x["epoch"])

        # Compute cross-artifact timestomping anomalies
        anomalies = [e for e in all_events if e.get("is_anomaly")]

        # Synthesize swimlanes and causality links
        extra = cls.build_causality_and_swimlanes(all_events, jobs=jobs)

        return {
            "total_events": len(all_events),
            "anomalies_count": len(anomalies),
            "events": all_events,
            "timestomping_report": {
                "detected": len(anomalies) > 0,
                "anomalies_count": len(anomalies),
                "anomalies": anomalies,
                "risk_rating": "CRITICAL" if any(a.get("severity") == "critical" for a in anomalies) else ("HIGH" if anomalies else "CLEAN")
            },
            "swimlanes": extra.get("swimlanes", []),
            "causality_links": extra.get("causality_links", [])
        }

    @classmethod
    def export_csv(cls, events: List[Dict[str, Any]]) -> str:
        """Export timeline events to CSV format for Plaso, Autopsy, or Excel."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Timestamp (UTC)", "Epoch", "Category", "Source", "Event Type", "Title", "Severity", "Anomaly", "Description"])
        for e in events:
            writer.writerow([
                e.get("timestamp"),
                e.get("epoch"),
                e.get("category"),
                e.get("source"),
                e.get("event_type"),
                e.get("title"),
                e.get("severity"),
                "YES" if e.get("is_anomaly") else "NO",
                e.get("description")
            ])
        return output.getvalue()
