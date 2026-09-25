import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.config import settings
from app.core.logging_config import logger
from app.core.file_isolation import JobWorkspace, sanitize_filename
from app.analyzers.base import Finding
from app.analyzers.identification import IdentificationAnalyzer
from app.analyzers.clamav_scanner import ClamAVScanner
from app.analyzers.pdf_analyzer import PDFAnalyzer
from app.analyzers.office_analyzer import OfficeAnalyzer
from app.analyzers.image_analyzer import ImageAnalyzer
from app.analyzers.active_content import ActiveContentAnalyzer
from app.analyzers.archive_analyzer import ArchiveAnalyzer
from app.analyzers.text_analyzer import TextAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.metadata_extractor import MetadataExtractor, StructuredMetadata
from app.analyzers.risk_engine import RiskEngine, RiskAssessment

from app.sanitizers.base import SanitizationOptions, SanitizationResult
from app.sanitizers.profiles import get_profile_options
from app.sanitizers.image_sanitizer import ImageSanitizer
from app.sanitizers.pdf_sanitizer import PDFSanitizer
from app.sanitizers.office_sanitizer import OfficeSanitizer
from app.sanitizers.svg_sanitizer import SVGSanitizer
from app.sanitizers.html_sanitizer import HTMLSanitizer
from app.sanitizers.archive_sanitizer import ArchiveSanitizer
from app.sanitizers.text_sanitizer import TextSanitizer
from app.network.screenshot_client import ScreenshotClient

class JobModel(BaseModel):
    job_id: str
    filename: str
    original_filename: str
    created_at: str
    state: str = "QUEUED"  # QUEUED, ANALYZING, ANALYZED, SANITIZING, VALIDATING, COMPLETED, FAILED
    progress: int = 0
    file_size: int = 0
    hashes: Dict[str, str] = Field(default_factory=dict)
    mime_type: str = "application/octet-stream"
    category: str = "binary"
    signature_description: str = ""
    risk: Optional[RiskAssessment] = None
    clamav: Dict[str, Any] = Field(default_factory=dict)
    metadata: Optional[StructuredMetadata] = None
    findings: List[Finding] = Field(default_factory=list)
    urls: List[Dict[str, Any]] = Field(default_factory=list)
    sanitization_options: Optional[SanitizationOptions] = None
    sanitization_result: Optional[SanitizationResult] = None
    validation: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    sanitized_file_path: Optional[str] = None

class JobManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._jobs: Dict[str, JobModel] = {}
                cls._instance._workspaces: Dict[str, JobWorkspace] = {}
        return cls._instance

    def create_job(self, file_bytes: bytes, raw_filename: str) -> JobModel:
        safe_name = sanitize_filename(raw_filename)
        workspace = JobWorkspace().create()
        job_id = workspace.job_id

        # Save original file securely
        original_path = workspace.original_file_path(safe_name)
        original_path.write_bytes(file_bytes)

        job = JobModel(
            job_id=job_id,
            filename=safe_name,
            original_filename=raw_filename,
            created_at=datetime.utcnow().isoformat() + "Z",
            state="QUEUED",
            progress=0,
            file_size=len(file_bytes)
        )

        with self._lock:
            self._jobs[job_id] = job
            self._workspaces[job_id] = workspace

        logger.info(f"Created Job {job_id} for file '{safe_name}' ({len(file_bytes)} bytes)")
        return job

    def get_job(self, job_id: str) -> Optional[JobModel]:
        return self._jobs.get(job_id)

    def get_workspace(self, job_id: str) -> Optional[JobWorkspace]:
        return self._workspaces.get(job_id)

    def list_jobs(self) -> List[JobModel]:
        return list(self._jobs.values())

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            ws = self._workspaces.pop(job_id, None)
            job = self._jobs.pop(job_id, None)
            if ws:
                ws.cleanup()
            return job is not None

    def execute_analysis_pipeline(self, job_id: str) -> JobModel:
        """
        Complete analysis pipeline:
        1. File Identification & Hashing
        2. ClamAV Antivirus Scanning
        3. Format-specific Security Analyzers
        4. URL Extraction & Pluggable Reputation & Screenshot
        5. Explainable Risk Evaluation & Recommendations
        """
        job = self.get_job(job_id)
        ws = self.get_workspace(job_id)
        if not job or not ws:
            raise ValueError(f"Job {job_id} not found")

        job.state = "ANALYZING"
        job.progress = 10

        try:
            original_path = ws.original_file_path(job.filename)
            findings: List[Finding] = []
            analysis_data: Dict[str, Any] = {}

            # 1. Identification Analyzer
            ident_analyzer = IdentificationAnalyzer()
            ident_res = ident_analyzer.analyze(original_path, job.filename, job.mime_type)
            findings.extend(ident_res.findings)
            job.hashes = ident_res.data["hashes"]
            job.mime_type = ident_res.data["detected_mime"]
            job.category = ident_res.data["category"]
            job.signature_description = ident_res.data["description"]
            is_mismatch = ident_res.data["is_mismatch"]
            job.progress = 25

            # 2. ClamAV Antivirus Scanner
            clamav_scanner = ClamAVScanner()
            av_res = clamav_scanner.analyze(original_path, job.filename, job.mime_type)
            findings.extend(av_res.findings)
            job.clamav = av_res.data
            job.progress = 40

            # 3. Format-specific Analyzers
            has_macros = False
            has_javascript = False
            has_path_traversal = False
            is_zip_bomb = False
            has_executable = (job.category == "executable")
            extracted_urls = set()

            if job.category == "pdf":
                pdf_res = PDFAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(pdf_res.findings)
                analysis_data["pdf"] = pdf_res.data
                has_javascript = pdf_res.data.get("has_javascript", False)
                for u in pdf_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "office":
                office_res = OfficeAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(office_res.findings)
                analysis_data["office"] = office_res.data
                has_macros = office_res.data.get("has_macros", False)
                for u in office_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "image":
                img_res = ImageAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(img_res.findings)
                analysis_data["image"] = img_res.data

            elif job.category in ["svg", "html"]:
                act_res = ActiveContentAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(act_res.findings)
                analysis_data["active_content"] = act_res.data
                has_javascript = act_res.data.get("has_javascript", False)
                for u in act_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "archive":
                arch_res = ArchiveAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(arch_res.findings)
                analysis_data["archive"] = arch_res.data
                has_path_traversal = arch_res.data.get("has_path_traversal", False)
                is_zip_bomb = arch_res.data.get("is_zip_bomb", False)
                has_executable = has_executable or arch_res.data.get("has_executables", False)

            elif job.category == "text":
                txt_res = TextAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(txt_res.findings)
                analysis_data["text"] = txt_res.data
                for u in txt_res.data.get("urls", []):
                    extracted_urls.add(u)

            job.progress = 65

            # 4. URL Analysis & Screenshots
            analyzed_urls = []
            analysis_data["urls"] = list(extracted_urls)

            for idx, url in enumerate(list(extracted_urls)[:15]):  # Analyze up to 15 URLs
                url_data = URLAnalyzer.analyze_url(url)
                # Attempt screenshot if SSRF-safe and within first 3 URLs
                if url_data.get("is_ssrf_safe") and idx < 3:
                    shot_name = f"screenshot_{idx}.png"
                    shot_path = ws.screenshots_dir / shot_name
                    success = ScreenshotClient.capture_screenshot(url, shot_path)
                    if success:
                        url_data["screenshot_available"] = True
                        url_data["screenshot_url"] = f"/api/jobs/{job_id}/screenshots/{shot_name}"
                analyzed_urls.append(url_data)

            job.urls = analyzed_urls
            job.progress = 80

            # 5. Metadata Consolidation
            job.metadata = MetadataExtractor.consolidate(
                filename=job.filename,
                file_size=job.file_size,
                mime_type=job.mime_type,
                hashes=job.hashes,
                analysis_data=analysis_data
            )

            # 6. Risk Evaluation & Recommendations
            job.findings = findings
            job.risk = RiskEngine.evaluate(
                findings=findings,
                clamav_status=job.clamav.get("status", "UNAVAILABLE"),
                category=job.category,
                has_macros=has_macros,
                has_javascript=has_javascript,
                has_path_traversal=has_path_traversal,
                is_zip_bomb=is_zip_bomb,
                has_executable=has_executable,
                is_mismatch=is_mismatch
            )

            job.state = "ANALYZED"
            job.progress = 100
            logger.info(f"Completed analysis for Job {job_id}: Risk={job.risk.level}, Findings={len(findings)}")
            return job

        except Exception as e:
            logger.error(f"Analysis failed for job {job_id}: {e}", exc_info=True)
            job.state = "FAILED"
            job.error_message = str(e)
            return job

    def execute_sanitization_pipeline(self, job_id: str, options: SanitizationOptions) -> JobModel:
        """
        Execute Content Disarm & Reconstruction (CDR) according to user options
        followed by post-sanitization validation.
        """
        job = self.get_job(job_id)
        ws = self.get_workspace(job_id)
        if not job or not ws:
            raise ValueError(f"Job {job_id} not found")

        # Security check: If original is MALICIOUS, do not silently sanitize
        if job.risk and job.risk.level == "MALICIOUS" and not options.profile == "maximum":
            raise ValueError("Sanitization blocked: Original file is flagged as active MALWARE.")

        job.state = "SANITIZING"
        job.progress = 20
        job.sanitization_options = options

        original_path = ws.original_file_path(job.filename)

        # Select target sanitizer
        sanitizer = self._select_sanitizer(job.category)
        if not sanitizer:
            job.state = "FAILED"
            job.error_message = f"No sanitizer available for category '{job.category}'"
            return job

        target_ext = None
        if options.convert_to_jpg:
            target_ext = "jpg"
        elif options.convert_to_png:
            target_ext = "png"
        elif options.convert_to_pdf:
            target_ext = "pdf"

        output_path = ws.sanitized_file_path(job.filename, target_ext)

        sanitization_res = sanitizer.sanitize(
            input_path=original_path,
            output_path=output_path,
            options=options,
            original_filename=job.filename
        )

        job.sanitization_result = sanitization_res
        if not sanitization_res.success:
            job.state = "FAILED"
            job.error_message = "\n".join(sanitization_res.warnings)
            return job

        job.sanitized_file_path = str(output_path)
        job.progress = 60

        # Post-Sanitization Validation
        return self.execute_post_sanitization_validation(job_id)

    def execute_post_sanitization_validation(self, job_id: str) -> JobModel:
        """
        Re-scans the newly generated sanitized file through the same pipeline
        and constructs the before/after verification matrix.
        """
        job = self.get_job(job_id)
        ws = self.get_workspace(job_id)
        if not job or not ws or not job.sanitized_file_path:
            raise ValueError("Cannot validate: sanitized file not ready")

        job.state = "VALIDATING"
        clean_path = Path(job.sanitized_file_path)

        # Compute clean file hashes
        clean_ident = IdentificationAnalyzer().analyze(clean_path, clean_path.name, "")
        clean_hashes = clean_ident.data["hashes"]
        clean_mime = clean_ident.data["detected_mime"]
        clean_size = clean_path.stat().st_size

        # ClamAV scan on clean file
        clean_av = ClamAVScanner().analyze(clean_path, clean_path.name, clean_mime)

        # Re-check active content / macros / metadata
        clean_js = False
        clean_macros = False
        clean_urls_count = 0
        clean_att_count = 0
        clean_meta_fields = 0

        if clean_ident.data["category"] == "pdf":
            p_res = PDFAnalyzer().analyze(clean_path, clean_path.name, clean_mime)
            clean_js = p_res.data.get("has_javascript", False)
            clean_urls_count = len(p_res.data.get("urls", []))
            clean_att_count = len(p_res.data.get("embedded_files", []))
            clean_meta_fields = sum(1 for v in p_res.data.get("metadata", {}).values() if v)

        elif clean_ident.data["category"] == "office":
            o_res = OfficeAnalyzer().analyze(clean_path, clean_path.name, clean_mime)
            clean_macros = o_res.data.get("has_macros", False)
            clean_urls_count = len(o_res.data.get("urls", []))
            clean_att_count = len(o_res.data.get("ole_objects", []))
            clean_meta_fields = len(o_res.data.get("metadata", {}))

        elif clean_ident.data["category"] == "image":
            i_res = ImageAnalyzer().analyze(clean_path, clean_path.name, clean_mime)
            clean_meta_fields = len(i_res.data.get("raw_metadata", {}))

        # Comparison Matrix
        orig_meta_count = job.metadata.total_fields if job.metadata else 0
        orig_urls_count = len(job.urls)
        orig_js = any(f.category == "javascript" for f in job.findings)
        orig_macros = any(f.category == "macro" for f in job.findings)
        orig_att = any("embedded" in f.category or "ole" in f.title.lower() for f in job.findings)

        validation_data = {
            "is_clean": (clean_av.data.get("status") != "MALICIOUS" and not clean_js and not clean_macros),
            "original": {
                "file_size": job.file_size,
                "sha256": job.hashes.get("sha256", "N/A"),
                "mime_type": job.mime_type,
                "metadata_count": orig_meta_count,
                "urls_count": orig_urls_count,
                "has_javascript": orig_js,
                "has_macros": orig_macros,
                "attachments_count": 1 if orig_att else 0,
            },
            "sanitized": {
                "file_size": clean_size,
                "sha256": clean_hashes.get("sha256", "N/A"),
                "mime_type": clean_mime,
                "metadata_count": clean_meta_fields,
                "urls_count": clean_urls_count,
                "has_javascript": clean_js,
                "has_macros": clean_macros,
                "attachments_count": clean_att_count,
            },
            "clamav_status": clean_av.data.get("status", "UNAVAILABLE"),
            "removed_items": job.sanitization_result.removed_items if job.sanitization_result else [],
            "warnings": job.sanitization_result.warnings if job.sanitization_result else []
        }

        job.validation = validation_data
        job.state = "COMPLETED"
        job.progress = 100
        logger.info(f"Post-sanitization validation completed for Job {job_id}: is_clean={validation_data['is_clean']}")
        return job

    def _select_sanitizer(self, category: str):
        if category == "image":
            return ImageSanitizer()
        elif category == "pdf":
            return PDFSanitizer()
        elif category == "office":
            return OfficeSanitizer()
        elif category == "svg":
            return SVGSanitizer()
        elif category == "html":
            return HTMLSanitizer()
        elif category == "archive":
            return ArchiveSanitizer()
        elif category == "text":
            return TextSanitizer()
        return None

job_manager = JobManager()
