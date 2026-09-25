from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from app.config import settings
from app.core.job_manager import job_manager
from app.core.logging_config import logger
from app.network.url_fetcher import URLFileFetcher, URLFetcherException

router = APIRouter(prefix="/files", tags=["Files"])

class FetchUrlRequest(BaseModel):
    url: str

SUPPORTED_FORMATS_CATALOG = [
    {
        "category": "Images",
        "extensions": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tiff"],
        "description": "Raster graphics and photographs containing metadata, geolocation, or embedded thumbnails.",
        "checks": [
            "EXIF metadata (hardware, serial number, lens info)",
            "GPS physical location coordinates (latitude, longitude, altitude)",
            "Author, artist, and copyright attribution tags",
            "Creation, digitization, and modification timestamps",
            "Embedded text comments and annotation chunks",
            "XMP and IPTC metadata structures",
            "Embedded thumbnails and preview streams",
            "Embedded URLs within metadata tags or comments",
            "ICC color profiles and alpha channel transparency"
        ],
        "sanitization_options": [
            "Strip all EXIF / IPTC / XMP metadata",
            "Remove GPS coordinates",
            "Remove author and copyright tags",
            "Strip timestamps",
            "Re-encode raw pixel buffer (purge steganographic/slack data)",
            "Convert to JPG or PNG",
            "Flatten image (composite transparency onto white canvas)"
        ]
    },
    {
        "category": "PDF Documents",
        "extensions": [".pdf", ".pdfa"],
        "description": "Portable Document Format files containing potential active content, embedded files, or exploits.",
        "checks": [
            "Document metadata (Author, Creator, Producer, Title, Dates)",
            "Active JavaScript actions and embedded script objects",
            "/Launch actions and automatic /OpenAction triggers",
            "Embedded file attachments and secondary document streams",
            "Interactive AcroForms and dynamic XML Forms Architecture (XFA)",
            "Hyperlinks and URI stream actions",
            "Incremental updates (revision history / shadow attacks)",
            "Exploit indicators, password protection, and structural integrity"
        ],
        "sanitization_options": [
            "Strip author, creator, and producer metadata",
            "Purge active JavaScript actions",
            "Remove /Launch commands and external triggers",
            "Purge embedded file attachments",
            "Remove AcroForm fields and dynamic XFA forms",
            "Strip external hyperlinks and URI actions",
            "Maximum Rasterization CDR (render every page to high-res image and rebuild clean PDF)"
        ]
    },
    {
        "category": "Microsoft Office Documents",
        "extensions": [".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".rtf", ".odt", ".ods", ".odp"],
        "description": "Word processing, spreadsheet, and presentation documents with macro or external reference capabilities.",
        "checks": [
            "Visual Basic for Applications (VBA) macros (vbaProject.bin)",
            "ActiveX controls and executable OLE storage streams",
            "Remote template injection (attachedTemplate relationships)",
            "External relationships and remote resource fetches",
            "Tracked changes (revisions, deletions, insertions)",
            "Internal author comments and reviewer notes",
            "Core and custom document metadata properties",
            "Hyperlinks embedded in markup or relationship files"
        ],
        "sanitization_options": [
            "Purge all VBA macro binary streams (vbaProject.bin)",
            "Strip embedded ActiveX and OLE storage objects",
            "Neutralize external relationships and remote template targets",
            "Scrub author, creator, and revision metadata from docProps",
            "Remove tracked revisions and internal comments",
            "Downgrade macroEnabled OpenXML container types to clean standard types"
        ]
    },
    {
        "category": "Archives",
        "extensions": [".zip", ".7z", ".tar", ".gz", ".tgz"],
        "description": "Compressed and uncompressed member archives with potential nested threats.",
        "checks": [
            "Directory traversal filenames (../../etc/passwd)",
            "Dangerous executable members (.exe, .dll, .bat, .cmd, .ps1, .vbs, .sh)",
            "Excessive compression ratios / zip bombs (>100:1 ratio)",
            "Nested archives and recursive member bombs",
            "Password-protected and encrypted members",
            "Absolute file paths and symlink targets"
        ],
        "sanitization_options": [
            "Exclude directory traversal filenames",
            "Purge executable scripts and binary payloads",
            "Safe unpack with strict size and member count limits",
            "Reconstruct clean ZIP archive containing only safe members"
        ]
    },
    {
        "category": "Vector Graphics & Active Web",
        "extensions": [".svg", ".html", ".htm"],
        "description": "Markup-based documents capable of browser execution, script injection, and credential harvesting.",
        "checks": [
            "Executable <script> elements and JavaScript code",
            "Inline DOM event handlers (onload, onerror, onclick, etc.)",
            "javascript: and data: URI pseudo-protocols",
            "Credential phishing forms (<form action=...>)",
            "External tracking beacons and remote images",
            "Embedded iframes (<iframe src=...>)",
            "Meta refresh redirects and suspicious external links"
        ],
        "sanitization_options": [
            "Strip all <script> blocks and executable code",
            "Remove inline event handlers (onload, onerror, etc.)",
            "Purge credential forms and submit buttons",
            "Decompose and strip embedded iframes",
            "Neutralize external tracker beacons",
            "Rasterize SVG to high-resolution clean PNG or JPG image"
        ]
    },
    {
        "category": "Plain Text & Spreadsheets",
        "extensions": [".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md"],
        "description": "Structured and tabular data susceptible to formula injection and encoding tampering.",
        "checks": [
            "CSV Formula / Dynamic Data Exchange (DDE) injection (=cmd|..., +powershell..., @SUM...)",
            "Character encoding detection and Byte Order Mark (BOM) inspection",
            "Suspicious shell command strings and dropper URLs",
            "XML External Entity (XXE) and billion laughs entity expansion markers",
            "Embedded URLs and remote web links"
        ],
        "sanitization_options": [
            "Escape spreadsheet formula execution prefixes with safe leading quote (')",
            "Normalize character encoding to standard UTF-8",
            "Strip dangerous BOM markers"
        ]
    }
]

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

        background_tasks.add_task(job_manager.execute_analysis_pipeline, job.job_id)

    return {"uploaded": len(created_jobs), "jobs": created_jobs}

@router.post("/fetch-url")
def fetch_file_from_url(
    payload: FetchUrlRequest,
    background_tasks: BackgroundTasks
):
    """
    Fetch a remote file from a user-supplied URL.
    Performs SSRF validation, threat reputation/watchlist checks, format verification,
    and enqueues the file into the security analysis and CDR pipeline.
    """
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        raw_bytes, filename, reputation = URLFileFetcher.fetch(url)
    except URLFetcherException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        logger.error(f"Unexpected error in URL file fetcher: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch remote file: {e}")

    job = job_manager.create_job(raw_bytes, filename)

    # Attach URL reputation to the job's URL explorer
    if reputation:
        job.urls.append(reputation)

    # Queue background analysis execution
    background_tasks.add_task(job_manager.execute_analysis_pipeline, job.job_id)

    return {
        "uploaded": 1,
        "jobs": [{
            "job_id": job.job_id,
            "filename": job.filename,
            "file_size": job.file_size,
            "state": job.state
        }],
        "source_url": url,
        "reputation": reputation
    }

@router.get("/supported-formats")
def get_supported_formats():
    """
    Return comprehensive catalog of supported file formats, security checks,
    and available sanitization / CDR transformations.
    """
    return {
        "total_categories": len(SUPPORTED_FORMATS_CATALOG),
        "categories": SUPPORTED_FORMATS_CATALOG
    }

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
