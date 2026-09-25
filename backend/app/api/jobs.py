from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
from typing import Optional
from datetime import datetime
from pydantic import BaseModel

from app.core.job_manager import job_manager
from app.sanitizers.base import SanitizationOptions
from app.sanitizers.profiles import get_profile_options
from app.core.logging_config import logger

router = APIRouter(prefix="/jobs", tags=["Jobs"])

class SanitizeRequest(BaseModel):
    profile: Optional[str] = "privacy"
    options: Optional[SanitizationOptions] = None

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
        "progress": job.progress,
        "file_size": job.file_size,
        "mime_type": job.mime_type,
        "category": job.category,
        "signature_description": job.signature_description,
        "risk_level": job.risk.level if job.risk else None,
        "error_message": job.error_message
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
        "state": job.state
    }

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

    if job.risk and job.risk.level == "MALICIOUS" and payload.profile != "maximum":
        raise HTTPException(
            status_code=403,
            detail="File contains active malware detected by antivirus scanner. Sanitization is restricted."
        )

    # Resolve options
    if payload.options:
        opts = payload.options
    elif payload.profile:
        opts = get_profile_options(payload.profile)
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
        "warnings": job.sanitization_result.warnings if job.sanitization_result else []
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

@router.get("/{job_id}/report")
def download_audit_report(job_id: str):
    """Generate and return structured security audit report in JSON format."""
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    report = {
        "report_type": "FileSanitizer Security & CDR Audit Report",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "job_id": job.job_id,
        "original_file": {
            "filename": job.filename,
            "file_size": job.file_size,
            "mime_type": job.mime_type,
            "category": job.category,
            "hashes": job.hashes
        },
        "security_analysis": {
            "risk_assessment": job.risk.dict() if job.risk else None,
            "antivirus_scan": job.clamav,
            "findings_count": len(job.findings),
            "findings": [f.dict() for f in job.findings],
            "discovered_urls_count": len(job.urls),
        },
        "sanitization": {
            "options": job.sanitization_options.dict() if job.sanitization_options else None,
            "result": job.sanitization_result.dict() if job.sanitization_result else None
        },
        "post_sanitization_validation": job.validation,
        "disclaimer": (
            "FileSanitizer performs automated security analysis and file sanitization. "
            "A 'clean' result indicates no known malicious content was detected by configured engines; "
            "it does not constitute an absolute guarantee of safety."
        )
    }

    from fastapi.encoders import jsonable_encoder
    return JSONResponse(
        content=jsonable_encoder(report),
        headers={"Content-Disposition": f"attachment; filename=FileSanitizer_Report_{job.job_id[:8]}.json"}
    )

@router.delete("/{job_id}")
def delete_job(job_id: str):
    """Immediately and securely purge job workspace and all temporary files."""
    success = job_manager.delete_job(job_id)
    if not success:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"success": True, "message": f"Workspace {job_id} deleted."}
