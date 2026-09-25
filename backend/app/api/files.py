from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from typing import List
from app.config import settings
from app.core.job_manager import job_manager
from app.core.logging_config import logger

router = APIRouter(prefix="/files", tags=["Files"])

@router.post("")
async def upload_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...)
):
    """
    Upload one or multiple files.
    Creates isolated job workspaces and queues security analysis asynchronously.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided.")

    created_jobs = []
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024

    for file in files:
        # Read content safely
        content = await file.read()
        if len(content) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File '{file.filename}' exceeds maximum allowed upload size ({settings.MAX_FILE_SIZE_MB} MB)."
            )

        job = job_manager.create_job(content, file.filename or "uploaded_file")
        created_jobs.append({
            "job_id": job.job_id,
            "filename": job.filename,
            "file_size": job.file_size,
            "state": job.state
        })

        # Queue background analysis execution
        background_tasks.add_task(job_manager.execute_analysis_pipeline, job.job_id)

    return {"uploaded": len(created_jobs), "jobs": created_jobs}

@router.get("")
def list_all_jobs():
    """List all currently active processing jobs."""
    jobs = job_manager.list_jobs()
    return [{
        "job_id": j.job_id,
        "filename": j.filename,
        "created_at": j.created_at,
        "state": j.state,
        "progress": j.progress,
        "risk_level": j.risk.level if j.risk else "PENDING",
        "file_size": j.file_size
    } for j in jobs]
