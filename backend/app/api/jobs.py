from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, Response
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import re
from pydantic import BaseModel

from app.core.job_manager import job_manager
from app.sanitizers.base import SanitizationOptions
from app.sanitizers.profiles import get_profile_options
from app.core.logging_config import logger
from app.core.forensic_report import ForensicReportGenerator

router = APIRouter(prefix="/jobs", tags=["Jobs"])

class CorrelateJobsRequest(BaseModel):
    job_ids: List[str]

class SanitizeRequest(BaseModel):
    profile: Optional[str] = "privacy"
    options: Optional[SanitizationOptions] = None

class UnlockRequest(BaseModel):
    password: str

class ReanalyzeJobRequest(BaseModel):
    override_extension: Optional[str] = None
    override_filename: Optional[str] = None

@router.post("/correlate")
def correlate_jobs(req: CorrelateJobsRequest):
    """Perform multi-artifact cross-correlation, BinDiff, timeline, and threat graph synthesis across workspace jobs."""
    if not req.job_ids:
        raise HTTPException(status_code=400, detail="No job_ids provided for correlation.")
    
    from app.core.incident_correlator import IncidentCorrelator
    result = IncidentCorrelator.correlate_jobs(req.job_ids)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Correlation failed."))
    return result

@router.get("/{job_id}")
def get_job_status(job_id: str):
    """Retrieve top-level job status and progression."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return {
        "job_id": job.job_id,
        "filename": job.filename,
        "original_filename": job.original_filename,
        "created_at": job.created_at,
        "state": job.state,
        "progress": getattr(job, "progress", 0),
        "current_step": getattr(job, "current_step", 0),
        "current_step_label": getattr(job, "current_step_label", ""),
        "file_size": job.file_size,
        "mime_type": job.mime_type,
        "category": job.category,
        "signature_description": job.signature_description,
        "risk_level": job.risk.level if job.risk else None,
        "is_password_protected": getattr(job, "is_password_protected", False),
        "is_unlocked": getattr(job, "is_unlocked", False),
        "error_message": job.error_message,
        "thumbnail_available": job.thumbnail_available,
        "thumbnail_url": job.thumbnail_url
    }

@router.get("/{job_id}/analysis")
def get_job_analysis(job_id: str):
    """Retrieve comprehensive security findings, risk assessment, hashes, and AV scan."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return {
        "job_id": job.job_id,
        "filename": job.filename,
        "file_size": job.file_size,
        "mime_type": job.mime_type,
        "category": job.category,
        "signature_description": job.signature_description,
        "hashes": job.hashes,
        "clamav": job.clamav,
        "risk": job.risk,
        "findings": job.findings,
        "extracted_code": job.extracted_code,
        "virustotal": job.virustotal,
        "hybrid_analysis": getattr(job, "hybrid_analysis", None),
        "threatfox": getattr(job, "threatfox", None),
        "malwarebazaar": getattr(job, "malwarebazaar", None),
        "circl": getattr(job, "circl", None),
        "yara": job.yara,
        "thumbnail_available": job.thumbnail_available,
        "thumbnail_url": job.thumbnail_url,
        "state": job.state,
        "progress": getattr(job, "progress", 0),
        "current_step": getattr(job, "current_step", 0),
        "current_step_label": getattr(job, "current_step_label", ""),
        "is_password_protected": getattr(job, "is_password_protected", False),
        "is_unlocked": getattr(job, "is_unlocked", False),
        "unlock_password": getattr(job, "unlock_password", None),
        "email_info": getattr(job, "email_info", None),
        "binary_info": getattr(job, "binary_info", None),
        "script_triage": getattr(job, "script_triage", None),
        "mitre_attack": getattr(job, "mitre_attack", []),
        "embedded_files": getattr(job, "embedded_files", []),
        "deobfuscation": getattr(job, "deobfuscation", None),
        "alienvault_otx": getattr(job, "alienvault_otx", None),
        "entropy_profile": getattr(job, "entropy_profile", None),
        "domain_info": getattr(job, "domain_info", None),
        "extension_info": getattr(job, "extension_info", None),
        "ai_image_provenance": getattr(job, "ai_image_provenance", None),
        "applescript_info": getattr(job, "applescript_info", None),
        "office_info": getattr(job, "office_info", None),
        "pdf_info": getattr(job, "pdf_info", None),
        "image_info": getattr(job, "image_info", None),
        "jar_info": getattr(job, "jar_info", None),
        "anti_analysis": getattr(job, "anti_analysis", None),
        "disabled_checks": getattr(job, "disabled_checks", []),
        "similar_samples": getattr(job, "similar_samples", []),
        "cdr_diff": getattr(job, "cdr_diff", None),
        "entity_graph": getattr(job, "entity_graph", None),
        "reanalysis_intel_diff": getattr(job, "reanalysis_intel_diff", None),
        "pcap_info": getattr(job, "pcap_info", None),
        "shellcode_info": getattr(job, "shellcode_info", None),
        "hta_info": getattr(job, "hta_info", None),
        "evtx_info": getattr(job, "evtx_info", None),
        "lnk_info": getattr(job, "lnk_info", None),
        "detection_rules": getattr(job, "detection_rules", None),
        "telemetry": getattr(job, "telemetry", None)
    }

@router.get("/{job_id}/detection-rules")
def get_job_detection_rules(job_id: str):
    """Retrieve auto-generated Microsoft Sentinel KQL queries and YARA detection rules."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    rules = getattr(job, "detection_rules", None)
    if not rules:
        try:
            from app.analyzers.detection_rules import DetectionRuleGenerator
            rules = DetectionRuleGenerator.generate_all(job)
            job.detection_rules = rules
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate detection rules: {e}")

    return rules

@router.get("/{job_id}/metadata")
def get_job_metadata(job_id: str):
    """Retrieve detailed structured metadata (general, document, location, camera, embedded)."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return job.metadata or {}

@router.get("/{job_id}/urls")
def get_job_urls(job_id: str):
    """Retrieve extracted URLs with reputation indicators and screenshot preview info."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return {
        "job_id": job.job_id,
        "total_urls": len(job.urls),
        "urls": job.urls
    }

@router.get("/{job_id}/screenshots/{filename}")
def get_job_screenshot(job_id: str, filename: str):
    """Serve sandboxed preview screenshot securely."""
    ws = job_manager.get_workspace(job_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    safe_path = (ws.screenshots_dir / filename).resolve()
    ws.assert_within_workspace(safe_path)

    if not safe_path.exists():
        raise HTTPException(status_code=404, detail="Screenshot not found.")

    return FileResponse(safe_path, media_type="image/png")

@router.get("/{job_id}/thumbnail")
def get_job_thumbnail(job_id: str):
    """Serve sandboxed safe visual preview thumbnail for the uploaded file."""
    ws = job_manager.get_workspace(job_id)
    if not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    thumb_path = (ws.base_dir / "thumbnail.png").resolve()
    if not thumb_path.exists():
        from app.core.thumbnail_generator import ThumbnailGenerator
        job = job_manager.get_job(job_id)
        if job:
            orig_path = ws.original_file_path(job.filename)
            if orig_path.exists():
                ThumbnailGenerator.generate_thumbnail(orig_path, job.category, thumb_path)

    if not thumb_path.exists():
        raise HTTPException(status_code=404, detail="Thumbnail not available.")

    return FileResponse(thumb_path, media_type="image/png")

@router.post("/{job_id}/sanitize")
def start_sanitization(
    job_id: str,
    payload: SanitizeRequest,
    background_tasks: BackgroundTasks
):
    """
    Trigger sanitization and CDR pipeline with chosen profile or custom options.
    """
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.state == "SANITIZING":
        raise HTTPException(status_code=400, detail="Sanitization is already in progress.")

    # Resolve options
    if payload.options:
        opts = payload.options
    elif payload.profile:
        opts = get_profile_options(payload.profile)
    elif job.risk and job.risk.level == "MALICIOUS":
        opts = get_profile_options("maximum")
    else:
        opts = get_profile_options("privacy")

    # Queue background sanitization
    background_tasks.add_task(job_manager.execute_sanitization_pipeline, job_id, opts)

    return {
        "job_id": job_id,
        "status": "QUEUED",
        "profile": opts.profile,
        "message": "Sanitization and post-sanitization validation pipeline queued."
    }

@router.post("/{job_id}/reanalyze")
def reanalyze_job(
    job_id: str,
    payload: ReanalyzeJobRequest,
    background_tasks: BackgroundTasks
):
    """
    Re-analyze the uploaded file under a different extension or MIME type format.
    Useful when MIME type confusion or extension spoofing is detected.
    """
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    orig_path = ws.original_file_path(job.filename)
    if not orig_path.exists():
        raise HTTPException(status_code=404, detail="Original file not found in sandbox.")

    file_bytes = orig_path.read_bytes()

    from app.core.file_isolation import sanitize_filename
    if payload.override_filename:
        new_filename = sanitize_filename(payload.override_filename.strip())
    elif payload.override_extension:
        ext = payload.override_extension.strip()
        if not ext.startswith("."):
            ext = f".{ext}"
        base = job.original_filename.rsplit(".", 1)[0] if "." in job.original_filename else job.original_filename
        new_filename = sanitize_filename(f"{base}{ext}")
    else:
        new_filename = job.filename

    new_job = job_manager.create_job(file_bytes, new_filename)
    background_tasks.add_task(job_manager.execute_analysis_pipeline, new_job.job_id)

    return {
        "job_id": new_job.job_id,
        "filename": new_job.filename,
        "state": new_job.state,
        "message": f"Re-analysis job queued as '{new_filename}'."
    }

@router.get("/{job_id}/result")
def get_sanitization_result(job_id: str):
    """Retrieve post-sanitization validation and before/after comparison matrix."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.state != "COMPLETED":
        return {
            "job_id": job.job_id,
            "state": job.state,
            "progress": job.progress,
            "is_ready": False
        }

    return {
        "job_id": job.job_id,
        "state": job.state,
        "is_ready": True,
        "sanitized_filename": job.sanitization_result.sanitized_filename if job.sanitization_result else None,
        "validation": job.validation,
        "removed_items": job.sanitization_result.removed_items if job.sanitization_result else [],
        "warnings": job.sanitization_result.warnings if job.sanitization_result else [],
        "cdr_diff": getattr(job, "cdr_diff", None)
    }

@router.get("/{job_id}/download")
def download_sanitized_file(job_id: str):
    """
    Download the sanitized clean file.
    Security policy strictly prevents accidental downloading of malicious original files.
    """
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    if not job.sanitized_file_path or job.state != "COMPLETED":
        raise HTTPException(status_code=400, detail="Sanitized file is not ready for download.")

    sanitized_path = Path(job.sanitized_file_path)
    ws.assert_within_workspace(sanitized_path)

    if not sanitized_path.exists():
        raise HTTPException(status_code=404, detail="Sanitized file not found on disk.")

    download_name = job.sanitization_result.sanitized_filename if job.sanitization_result else f"clean_{job.filename}"

    return FileResponse(
        path=sanitized_path,
        filename=download_name,
        media_type="application/octet-stream"
    )

@router.post("/{job_id}/unlock")
def unlock_job(job_id: str, req: UnlockRequest):
    """Attempt to decrypt a password-protected file with the user-supplied password and re-run analysis."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if not req.password:
        raise HTTPException(status_code=400, detail="Password must not be empty.")

    try:
        updated_job = job_manager.unlock_and_reanalyze(job_id, req.password)
        return {
            "success": True,
            "job_id": updated_job.job_id,
            "is_unlocked": updated_job.is_unlocked,
            "state": updated_job.state,
            "message": "Password accepted and document decrypted!" if updated_job.is_unlocked else "Password was incorrect. File remains encrypted."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{job_id}/report")
def download_forensic_report(
    job_id: str,
    format: Optional[str] = Query(None, description="Report format: 'html' for printable visual dossier, 'json' for SIEM/SOAR incident export")
):
    """Generate and export comprehensive forensic security and CDR audit dossier."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    report_data = ForensicReportGenerator.build_report_data(job)
    safe_name = job.filename.replace(" ", "_")

    if format and format.lower() == "html":
        html_content = ForensicReportGenerator.generate_html_report(report_data)
        return HTMLResponse(
            content=html_content,
            headers={"Content-Disposition": f"inline; filename=Forensic_Report_{safe_name}.html"}
        )

    # Default to structured JSON incident export
    from fastapi.encoders import jsonable_encoder
    return JSONResponse(
        content=jsonable_encoder(report_data),
        headers={"Content-Disposition": f"attachment; filename=FileSanitizer_Report_{safe_name}.json"}
    )

@router.get("/{job_id}/attack-navigator")
def download_attack_navigator_layer(job_id: str):
    """Generate and export official MITRE ATT&CK Navigator v4.5 JSON layer for this job."""
    from app.analyzers.mitre_attack import MitreAttackMapper
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    techniques = getattr(job, "mitre_attack", [])
    layer_data = MitreAttackMapper.generate_navigator_layer(
        techniques=techniques,
        filename=job.original_filename or job.filename
    )
    clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', job.filename)
    return JSONResponse(
        content=layer_data,
        headers={"Content-Disposition": f"attachment; filename=ATTACK_Navigator_{clean_name}.json"}
    )


@router.get("/{job_id}/stix-export")
def download_stix_bundle(job_id: str):
    """Generate and export OASIS STIX 2.1 JSON incident and threat bundle."""
    from app.analyzers.stix_exporter import Stix21Exporter
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    bundle_data = Stix21Exporter.generate_bundle(job)
    clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', job.filename)
    return JSONResponse(
        content=bundle_data,
        headers={"Content-Disposition": f"attachment; filename=STIX21_{clean_name}.json"}
    )


@router.get("/{job_id}/raw-content")
def get_raw_file_content(job_id: str, offset: int = 0, length: int = 150000):
    """
    Returns raw file data for forensic inspection.
    Includes text content (if utf-8 decodeable), base64 encoded bytes for hex viewing,
    total file size, and chunk info.
    """
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    original_path = ws.original_file_path(job.filename)
    ws.assert_within_workspace(original_path)

    if not original_path.exists():
        raise HTTPException(status_code=404, detail="Original file not found on disk.")

    file_size = original_path.stat().st_size
    read_length = min(max(length, 1), 250000)
    with open(original_path, "rb") as f:
        f.seek(max(0, offset))
        chunk = f.read(read_length)

    import base64
    b64 = base64.b64encode(chunk).decode("ascii")
    text_content = chunk.decode("utf-8", errors="replace")

    return {
        "job_id": job_id,
        "filename": job.filename,
        "category": job.category,
        "file_size": file_size,
        "offset": offset,
        "length": len(chunk),
        "is_truncated": (offset + len(chunk)) < file_size,
        "b64": b64,
        "text": text_content
    }


class DeobfuscateRequest(BaseModel):
    text: Optional[str] = None
    operation: Optional[str] = "analyze"  # analyze, rot13, rot47, caesar, html, url, base85, reverse, defang, refang, ip_convert


@router.post("/{job_id}/deobfuscate")
def run_deobfuscator(job_id: str, req: Optional[DeobfuscateRequest] = None):
    """Run forensic string deobfuscator on extracted code or custom text."""
    from app.analyzers.deobfuscator import Deobfuscator
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    input_text = ""
    if req and req.text:
        input_text = req.text
    elif job.extracted_code:
        input_text = job.extracted_code.get("code", "")

    op = (req.operation or "analyze").lower() if req else "analyze"

    # Specific CyberChef operations
    if op == "rot13":
        return {"operation": op, "result": Deobfuscator.rot13(input_text)}
    elif op == "rot47":
        return {"operation": op, "result": Deobfuscator.rot47(input_text)}
    elif op == "caesar":
        return {"operation": op, "candidates": Deobfuscator.caesar_bruteforce(input_text)}
    elif op == "html":
        return {"operation": op, "result": Deobfuscator.html_entity_decode(input_text)}
    elif op == "url":
        return {"operation": op, "result": Deobfuscator.url_double_decode(input_text)}
    elif op == "base85":
        decoded = Deobfuscator.base85_decode(input_text)
        return {"operation": op, "result": decoded if decoded is not None else "Invalid Base85/Ascii85 stream"}
    elif op == "reverse":
        return {"operation": op, "result": Deobfuscator.reverse_string(input_text)}
    elif op == "defang":
        return {"operation": op, "result": Deobfuscator.defang_ioc(input_text)}
    elif op == "refang":
        return {"operation": op, "result": Deobfuscator.refang_ioc(input_text)}
    elif op == "ip_convert":
        return {"operation": op, "result": Deobfuscator.convert_ip_formats(input_text)}

    # Default: automated forensic analysis
    if not input_text:
        ws = job_manager.get_workspace(job_id)
        if ws:
            orig = ws.original_file_path(job.filename)
            if orig.exists():
                try:
                    raw_bytes = orig.read_bytes()[:100000]
                    return Deobfuscator.analyze_payload(raw_bytes)
                except Exception:
                    pass
        return {"has_deobfuscated_content": False, "summary": "No extracted text or binary content available for deobfuscation."}

    return Deobfuscator.analyze_payload(input_text)


@router.get("/{job_id}/email/attachments/{att_index}/download")
def download_email_attachment(job_id: str, att_index: int):
    """Safely download an extracted email attachment."""
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    email_info = getattr(job, "email_info", None)
    if not email_info or "attachments" not in email_info:
        raise HTTPException(status_code=404, detail="No email attachments found for this job.")

    attachments = email_info.get("attachments", [])
    target_att = None
    for att in attachments:
        if att.get("index") == att_index:
            target_att = att
            break

    if not target_att:
        raise HTTPException(status_code=404, detail=f"Attachment index {att_index} not found.")

    saved_path_str = target_att.get("saved_path")
    if not saved_path_str:
        raise HTTPException(status_code=404, detail="Attachment file not saved on disk.")

    file_path = Path(saved_path_str)
    ws.assert_within_workspace(file_path)

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Attachment file missing from workspace.")

    safe_name = target_att.get("filename") or f"attachment_{att_index}.bin"
    return FileResponse(
        path=file_path,
        filename=safe_name,
        media_type=target_att.get("content_type") or "application/octet-stream"
    )

@router.post("/{job_id}/email/attachments/{att_index}/analyze")
def analyze_email_attachment(
    job_id: str,
    att_index: int,
    background_tasks: BackgroundTasks
):
    """Submit an extracted email attachment as a new analysis job in FileSanitizer."""
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    email_info = getattr(job, "email_info", None)
    if not email_info or "attachments" not in email_info:
        raise HTTPException(status_code=404, detail="No attachments found for this email.")

    attachments = email_info.get("attachments", [])
    target_att = None
    for att in attachments:
        if att.get("index") == att_index:
            target_att = att
            break

    if not target_att:
        raise HTTPException(status_code=404, detail=f"Attachment index {att_index} not found.")

    saved_path_str = target_att.get("saved_path")
    if not saved_path_str:
        raise HTTPException(status_code=404, detail="Attachment file not saved.")

    file_path = Path(saved_path_str)
    ws.assert_within_workspace(file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Attachment file not found on disk.")

    file_bytes = file_path.read_bytes()
    att_name = target_att.get("filename") or f"attachment_{att_index}.bin"

    # Create new analysis job and queue background pipeline
    new_job = job_manager.create_job(file_bytes=file_bytes, raw_filename=att_name)
    background_tasks.add_task(job_manager.execute_analysis_pipeline, new_job.job_id)

    return {
        "success": True,
        "job_id": new_job.job_id,
        "filename": new_job.filename,
        "message": f"Attachment '{att_name}' queued for analysis."
    }

@router.get("/{job_id}/binary/dump-section")
def dump_binary_section(job_id: str, name: str = Query(..., description="Section name e.g. .text, .rsrc")):
    """Extract and download a specific section from an analyzed PE binary."""
    from app.analyzers.executable_analyzer import ExecutableAnalyzer

    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    orig_path = ws.original_file_path(job.filename)
    if not orig_path.exists():
        raise HTTPException(status_code=404, detail="Original binary not found in workspace.")

    sec_bytes = ExecutableAnalyzer.dump_section(orig_path, name)
    if sec_bytes is None:
        raise HTTPException(status_code=404, detail=f"Section '{name}' not found in executable.")

    clean_sec_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name.lstrip('.'))
    clean_job_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', job.filename)
    download_filename = f"{clean_job_name}_section_{clean_sec_name}.bin"

    return Response(
        content=sec_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
    )

@router.get("/{job_id}/binary/dump-resource")
def dump_binary_resource(
    job_id: str,
    type: str = Query(..., description="Resource type name or integer ID"),
    name: str = Query(..., description="Resource name or ID")
):
    """Extract and download a specific resource from an analyzed PE binary."""
    from app.analyzers.executable_analyzer import ExecutableAnalyzer

    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    orig_path = ws.original_file_path(job.filename)
    if not orig_path.exists():
        raise HTTPException(status_code=404, detail="Original binary not found in workspace.")

    res_bytes = ExecutableAnalyzer.dump_resource(orig_path, type, name)
    if res_bytes is None:
        raise HTTPException(status_code=404, detail=f"Resource '{type}/{name}' not found in executable.")

    clean_t = re.sub(r'[^a-zA-Z0-9_-]', '_', type)
    clean_n = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
    clean_job_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', job.filename)
    download_filename = f"{clean_job_name}_res_{clean_t}_{clean_n}.bin"

    return Response(
        content=res_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=\"{download_filename}\""}
    )

@router.get("/{job_id}/embedded-files")
def get_job_embedded_files(job_id: str):
    """Retrieve list of embedded files and payloads extracted from document or binary."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    files = getattr(job, "embedded_files", [])
    return {
        "job_id": job.job_id,
        "total": len(files),
        "files": files
    }

@router.get("/{job_id}/embedded-files/{file_id}/download")
def download_embedded_file(job_id: str, file_id: int):
    """Securely download an extracted embedded file payload."""
    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    embedded_list = getattr(job, "embedded_files", [])
    target = next((item for item in embedded_list if item.get("id") == file_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Embedded file not found.")

    disk_filename = target.get("disk_filename")
    if not disk_filename:
        raise HTTPException(status_code=404, detail="Embedded file record is missing disk filename.")

    file_path = (ws.extracted_dir / disk_filename).resolve()
    ws.assert_within_workspace(file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Extracted embedded file not found on disk.")

    download_name = target.get("name") or f"embedded_{file_id}.bin"
    return FileResponse(
        file_path,
        media_type=target.get("mime_type", "application/octet-stream"),
        filename=download_name
    )

@router.post("/{job_id}/embedded-files/{file_id}/analyze")
def analyze_embedded_file(job_id: str, file_id: int, background_tasks: BackgroundTasks):
    """Spawn an independent analysis pipeline job for an extracted embedded file."""
    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    embedded_list = getattr(job, "embedded_files", [])
    target = next((item for item in embedded_list if item.get("id") == file_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Embedded file not found.")

    disk_filename = target.get("disk_filename")
    if not disk_filename:
        raise HTTPException(status_code=404, detail="Embedded file record is missing disk filename.")

    file_path = (ws.extracted_dir / disk_filename).resolve()
    ws.assert_within_workspace(file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Extracted embedded file not found on disk.")

    file_bytes = file_path.read_bytes()
    raw_name = target.get("name") or f"embedded_{file_id}.bin"

    new_job = job_manager.create_job(file_bytes=file_bytes, raw_filename=raw_name)
    background_tasks.add_task(job_manager.execute_analysis_pipeline, new_job.job_id)

    return {
        "success": True,
        "job_id": new_job.job_id,
        "filename": new_job.filename,
        "message": f"Embedded file '{raw_name}' queued for independent analysis."
    }

@router.get("/{job_id}/pcap/files/{file_id}/download")
def download_pcap_carved_file(job_id: str, file_id: int):
    """Download a carved/extracted file artifact from PCAP capture."""
    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    carved_list = getattr(job, "pcap_info", {}).get("carved_files", []) if getattr(job, "pcap_info", None) else []
    target = next((item for item in carved_list if item.get("id") == file_id), None)
    if not target:
        embedded_list = getattr(job, "embedded_files", [])
        target = next((item for item in embedded_list if item.get("id") == file_id), None)

    if not target:
        raise HTTPException(status_code=404, detail="Carved file not found.")

    disk_filename = target.get("disk_filename")
    if not disk_filename:
        raise HTTPException(status_code=404, detail="Carved file record is missing disk filename.")

    file_path = (ws.extracted_dir / disk_filename).resolve()
    ws.assert_within_workspace(file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Carved file not found on disk.")

    download_name = target.get("filename") or target.get("name") or f"carved_{file_id}.bin"
    return FileResponse(
        file_path,
        media_type=target.get("mime_type", "application/octet-stream"),
        filename=download_name
    )

@router.post("/{job_id}/pcap/files/{file_id}/analyze")
def analyze_pcap_carved_file(job_id: str, file_id: int, background_tasks: BackgroundTasks):
    """Spawn an independent analysis pipeline job for a carved PCAP artifact."""
    ws = job_manager.get_workspace(job_id)
    job = job_manager.get_job(job_id)
    if not ws or not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    carved_list = getattr(job, "pcap_info", {}).get("carved_files", []) if getattr(job, "pcap_info", None) else []
    target = next((item for item in carved_list if item.get("id") == file_id), None)
    if not target:
        embedded_list = getattr(job, "embedded_files", [])
        target = next((item for item in embedded_list if item.get("id") == file_id), None)

    if not target:
        raise HTTPException(status_code=404, detail="Carved file not found.")

    disk_filename = target.get("disk_filename")
    if not disk_filename:
        raise HTTPException(status_code=404, detail="Carved file record is missing disk filename.")

    file_path = (ws.extracted_dir / disk_filename).resolve()
    ws.assert_within_workspace(file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Carved file not found on disk.")

    file_bytes = file_path.read_bytes()
    raw_name = target.get("filename") or target.get("name") or f"carved_{file_id}.bin"

    new_job = job_manager.create_job(file_bytes=file_bytes, raw_filename=raw_name)
    background_tasks.add_task(job_manager.execute_analysis_pipeline, new_job.job_id)

    return {
        "success": True,
        "job_id": new_job.job_id,
        "filename": new_job.filename,
        "message": f"Carved PCAP artifact '{raw_name}' queued for independent security analysis."
    }

@router.get("/{job_id}/entropy")
def get_job_entropy(job_id: str):
    """Retrieve deep-dive Shannon entropy sliding-window profile, Chi-Square, and byte frequencies."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    profile = getattr(job, "entropy_profile", None)
    if not profile:
        ws = job_manager.get_workspace(job_id)
        if ws:
            orig_path = ws.original_file_path(job.filename)
            if orig_path.exists():
                from app.analyzers.entropy_analyzer import EntropyAnalyzer
                profile = EntropyAnalyzer.analyze_bytes(orig_path.read_bytes())
                job.entropy_profile = profile
    return profile or {}

@router.get("/{job_id}/timeline")
def get_job_timeline(job_id: str, mode: str = "standard"):
    """Retrieve chronological forensic event reconstruction and timestomping anomaly timeline."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    from app.analyzers.forensic_timeline import ForensicTimelineBuilder
    if mode.lower() == "super":
        all_jobs = [job]
        if hasattr(job_manager, "_jobs") and isinstance(job_manager._jobs, dict):
            for oid, ojob in job_manager._jobs.items():
                if oid != job_id and ojob not in all_jobs:
                    all_jobs.append(ojob)
        res = ForensicTimelineBuilder.generate_super_timeline(all_jobs)
        res["job_id"] = job.job_id
        return res
    else:
        events = ForensicTimelineBuilder.generate_timeline(job)
        anomalies = [e for e in events if e.get("is_anomaly")]
        extra = ForensicTimelineBuilder.build_causality_and_swimlanes(events, jobs=[job])
        return {
            "job_id": job.job_id,
            "total_events": len(events),
            "anomalies_count": len(anomalies),
            "events": events,
            "timestomping_report": {
                "detected": len(anomalies) > 0,
                "anomalies_count": len(anomalies),
                "anomalies": anomalies,
                "risk_rating": "CRITICAL" if any(a.get("severity") == "critical" for a in anomalies) else ("HIGH" if anomalies else "CLEAN")
            },
            "swimlanes": extra.get("swimlanes", []),
            "causality_links": extra.get("causality_links", [])
        }

@router.get("/{job_id}/timeline/export")
def export_job_timeline(job_id: str, format: str = "json"):
    """Export forensic event timeline as RFC-4180 CSV or JSON."""
    import json
    from datetime import timezone
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    from app.analyzers.forensic_timeline import ForensicTimelineBuilder
    events = ForensicTimelineBuilder.generate_timeline(job)
    safe_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', job.filename)

    if format.lower() == "csv":
        csv_data = ForensicTimelineBuilder.export_csv(events)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="forensic_timeline_{safe_name}.csv"'}
        )
    else:
        json_data = json.dumps({
            "job_id": job.job_id,
            "filename": job.filename,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "events": events
        }, indent=2)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="forensic_timeline_{safe_name}.json"'}
        )

@router.get("/{job_id}/pdf/streams/{xref}")
def get_pdf_object_stream(job_id: str, xref: int):
    """Retrieve decompressed stream content, dictionary header, and hex representation for a specific PDF XRef object."""
    job = job_manager.get_job(job_id)
    ws = job_manager.get_workspace(job_id)
    if not job or not ws:
        raise HTTPException(status_code=404, detail="Job not found.")

    original_path = ws.original_file_path(job.filename)
    if not original_path.exists():
        raise HTTPException(status_code=404, detail="Original file not found on disk.")

    try:
        import fitz
        from app.analyzers.pdf_analyzer import _format_hex_preview
        doc = fitz.open(original_path)
        if xref < 1 or xref >= doc.xref_length():
            doc.close()
            raise HTTPException(status_code=404, detail=f"XRef {xref} out of bounds.")

        raw_dict = doc.xref_object(xref)
        is_stream = doc.xref_is_stream(xref)
        stream_bytes = doc.xref_stream(xref) if is_stream else b""
        doc.close()

        is_text = False
        text_content = ""
        if stream_bytes:
            try:
                text_content = stream_bytes.decode('utf-8')
                is_text = True
            except Exception:
                try:
                    text_content = stream_bytes.decode('latin-1')
                    is_text = True
                except Exception:
                    text_content = ""

        import base64
        return {
            "job_id": job_id,
            "xref": xref,
            "is_stream": is_stream,
            "size": len(stream_bytes),
            "raw_dict": raw_dict,
            "is_text": is_text,
            "text_content": text_content,
            "b64_content": base64.b64encode(stream_bytes).decode('ascii') if stream_bytes else "",
            "hex_dump": _format_hex_preview(stream_bytes, max_len=4096) if stream_bytes else ""
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to inspect PDF object #{xref}: {e}")

@router.delete("/{job_id}")
def delete_job(job_id: str):
    """Immediately and securely purge job workspace and all temporary files."""
    success = job_manager.delete_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"success": True, "message": f"Workspace {job_id} deleted."}
