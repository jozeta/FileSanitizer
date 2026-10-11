import json
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict

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
from app.analyzers.email_analyzer import EmailAnalyzer
from app.sanitizers.email_sanitizer import EmailSanitizer
from app.analyzers.executable_analyzer import ExecutableAnalyzer
from app.sanitizers.executable_sanitizer import ExecutableSanitizer
from app.network.screenshot_client import ScreenshotClient

from app.core.settings_store import settings_store
from app.core.yara_manager import yara_manager
from app.analyzers.virustotal_client import VirusTotalClient
from app.analyzers.ocr_analyzer import OCRAnalyzer
from app.analyzers.watchlist_analyzer import WatchlistAnalyzer
from app.core.thumbnail_generator import ThumbnailGenerator

def is_finding_suppressed(finding: Any, disabled_checks: List[str]) -> bool:
    """Check if a finding should be suppressed based on user-disabled format checks."""
    if not disabled_checks:
        return False
    title_lower = (getattr(finding, "title", "") or (finding.get("title", "") if isinstance(finding, dict) else "")).lower()
    cat_lower = (getattr(finding, "category", "") or (finding.get("category", "") if isinstance(finding, dict) else "")).lower()
    desc_lower = (getattr(finding, "description", "") or (finding.get("description", "") if isinstance(finding, dict) else "")).lower()

    check_keywords = {
        "check_ai_provenance": ["synthetic ai", "provenance", "c2pa", "generative ai", "diffusion"],
        "check_steganography_slack": ["steganography", "slack space", "padding", "steghide"],
        "check_exif": ["exif", "metadata"],
        "check_gps": ["gps", "location coordinates"],
        "check_tracking_pixels": ["tracking pixel", "beacon", "web beacon"],
        "check_spf_dkim_dmarc": ["spf", "dkim", "dmarc"],
        "check_thread_hijacking": ["thread hijacking", "in-reply-to mismatch"],
        "check_phishing_urgency": ["phishing", "urgency", "social engineering"],
        "check_vba_macros": ["macro", "vba", "autoopen", "document_open"],
        "check_vba_stomping": ["stomping", "p-code"],
        "check_dde_links": ["dde", "dynamic data exchange"],
        "check_remote_templates": ["remote template", "attachedtemplate"],
        "check_javascript": ["javascript", "/js", "eval(", "unescape("],
        "check_launch_actions": ["/launch", "launch action"],
        "check_open_actions": ["/openaction", "open action"],
        "check_xfa_acroforms": ["xfa", "acroform"],
        "check_zip_bomb": ["zip bomb", "compression ratio", "decompression bomb"],
        "check_path_traversal": ["path traversal", "directory traversal", "../"],
        "check_sections_entropy": ["entropy", "high entropy section"],
        "check_packers_upx": ["upx", "packed executable", "packer"],
        "check_authenticode_signature": ["authenticode", "digital signature", "invalid signature"],
        "check_anti_analysis": ["anti-debug", "sandbox evasion", "virtual machine detection", "anti-analysis"],
        "check_obfuscation": ["obfuscated", "obfuscation"],
        "check_base64_decode": ["base64", "encoded payload"],
        "check_process_spawning": ["spawns process", "powershell.exe", "cmd.exe", "wscript"],
        "check_network_cradle": ["download cradle", "webclient", "curl", "invoke-webrequest"],
        "check_manifest_permissions": ["dangerous permission", "broad permissions"],
    }

    for check in disabled_checks:
        kws = check_keywords.get(check, [])
        for kw in kws:
            if kw in title_lower or kw in cat_lower or kw in desc_lower:
                return True
    return False

class JobModel(BaseModel):
    job_id: str
    filename: str
    original_filename: str
    created_at: str
    state: str = "QUEUED"  # QUEUED, ANALYZING, ANALYZED, SANITIZING, VALIDATING, COMPLETED, FAILED
    progress: int = 0
    current_step: int = 0
    current_step_label: str = "Queued for analysis..."
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
    extracted_code: Optional[Dict[str, Any]] = None
    virustotal: Optional[Dict[str, Any]] = None
    hybrid_analysis: Optional[Dict[str, Any]] = None
    threatfox: Optional[Dict[str, Any]] = None
    malwarebazaar: Optional[Dict[str, Any]] = None
    circl: Optional[Dict[str, Any]] = None
    alienvault_otx: Optional[Dict[str, Any]] = None
    entropy_profile: Optional[Dict[str, Any]] = None
    yara: Optional[Dict[str, Any]] = None
    thumbnail_available: bool = False
    thumbnail_url: Optional[str] = None
    sanitization_options: Optional[SanitizationOptions] = None
    sanitization_result: Optional[SanitizationResult] = None
    validation: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    sanitized_file_path: Optional[str] = None
    is_password_protected: bool = False
    is_unlocked: bool = False
    unlock_password: Optional[str] = None
    email_info: Optional[Dict[str, Any]] = None
    binary_info: Optional[Dict[str, Any]] = None
    script_triage: Optional[Dict[str, Any]] = None
    mitre_attack: List[Dict[str, Any]] = Field(default_factory=list)
    embedded_files: List[Dict[str, Any]] = Field(default_factory=list)
    deobfuscation: Optional[Dict[str, Any]] = None
    domain_info: Optional[Dict[str, Any]] = None
    extension_info: Optional[Dict[str, Any]] = None
    ai_image_provenance: Optional[Dict[str, Any]] = None
    applescript_info: Optional[Dict[str, Any]] = None
    office_info: Optional[Dict[str, Any]] = None
    pdf_info: Optional[Dict[str, Any]] = None
    image_info: Optional[Dict[str, Any]] = None
    jar_info: Optional[Dict[str, Any]] = None
    anti_analysis: Optional[Dict[str, Any]] = None
    disabled_checks: List[str] = Field(default_factory=list)
    similar_samples: List[Dict[str, Any]] = Field(default_factory=list)
    cdr_diff: Optional[Dict[str, Any]] = None
    entity_graph: Optional[Dict[str, Any]] = None
    reanalysis_intel_diff: Optional[Dict[str, Any]] = None
    pcap_info: Optional[Dict[str, Any]] = None
    shellcode_info: Optional[Dict[str, Any]] = None
    hta_info: Optional[Dict[str, Any]] = None
    evtx_info: Optional[Dict[str, Any]] = None
    lnk_info: Optional[Dict[str, Any]] = None
    archive_info: Optional[Dict[str, Any]] = None
    analysis_data: Optional[Dict[str, Any]] = None
    detection_rules: Optional[Dict[str, Any]] = None
    telemetry: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(extra="allow")

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

    def create_job(self, file_bytes: bytes, raw_filename: str, password: Optional[str] = None) -> JobModel:
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
            file_size=len(file_bytes),
            unlock_password=password
        )

        with self._lock:
            self._jobs[job_id] = job
            self._workspaces[job_id] = workspace

        # Record initial upload in history
        try:
            settings_store.record_upload_history({
                "job_id": job.job_id,
                "filename": job.original_filename,
                "uploaded_at": job.created_at,
                "category": "pending",
                "mime_type": "application/octet-stream",
                "file_size": job.file_size,
                "risk_level": "ANALYZING",
                "verdict": "Analyzing...",
                "sha256": "",
                "md5": "",
                "findings_count": 0,
                "findings": [],
                "vt_score": None,
                "vt_ratio": None,
                "vt_details": None,
                "clamav": "PENDING",
                "clamav_details": None,
                "mitre_count": 0,
                "mitre_details": [],
            })
        except Exception as te:
            logger.debug(f"Initial history record error: {te}")

        logger.info(f"Created Job {job_id} for file '{safe_name}' ({len(file_bytes)} bytes)")
        self._save_job_to_disk(job)
        return job

    def _save_job_to_disk(self, job: JobModel) -> None:
        """Persist serialized job state to disk in the job workspace directory."""
        try:
            ws = self._workspaces.get(job.job_id) or JobWorkspace(job.job_id)
            if ws and ws.base_dir.exists():
                state_file = ws.base_dir / "job_state.json"
                state_file.write_text(job.model_dump_json())
        except Exception as e:
            logger.debug(f"Job disk save note for {job.job_id}: {e}")

    def _load_job_from_disk(self, job_id: str) -> Optional[JobModel]:
        """Attempt to recover and deserialize a job state file from its disk workspace."""
        try:
            ws = JobWorkspace(job_id)
            state_file = ws.base_dir / "job_state.json"
            if state_file.exists():
                data = json.loads(state_file.read_text())
                job = JobModel.model_validate(data)
                with self._lock:
                    self._jobs[job_id] = job
                    self._workspaces[job_id] = ws
                logger.info(f"Restored Job {job_id} ('{job.filename}') from disk workspace.")
                return job
        except Exception as e:
            logger.debug(f"Job disk restore note for {job_id}: {e}")
        return None

    def get_job(self, job_id: str) -> Optional[JobModel]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                return job
        return self._load_job_from_disk(job_id)

    def get_workspace(self, job_id: str) -> Optional[JobWorkspace]:
        with self._lock:
            ws = self._workspaces.get(job_id)
            if ws:
                return ws
        ws = JobWorkspace(job_id)
        if ws.base_dir.exists():
            with self._lock:
                self._workspaces[job_id] = ws
            return ws
        return None

    def list_jobs(self) -> List[JobModel]:
        # Merge in-memory jobs with disk workspaces
        jobs_map = dict(self._jobs)
        try:
            jobs_dir = Path(settings.JOBS_DIR).resolve()
            if jobs_dir.exists():
                for sub in jobs_dir.iterdir():
                    if sub.is_dir() and sub.name not in jobs_map:
                        state_file = sub / "job_state.json"
                        if state_file.exists():
                            loaded = self._load_job_from_disk(sub.name)
                            if loaded:
                                jobs_map[sub.name] = loaded
        except Exception as e:
            logger.debug(f"List jobs disk scan note: {e}")
        return list(jobs_map.values())

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            ws = self._workspaces.pop(job_id, None)
            job = self._jobs.pop(job_id, None)
            if not ws:
                ws = JobWorkspace(job_id)
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
        pipeline_start_time = time.time()
        step_timings = []
        checks_executed = []
        network_lookups_count = 0
        services_contacted = []
        pipeline_errors = []

        job.progress = 5
        job.current_step = 1
        job.current_step_label = "File Identification & Cryptographic Hashing"

        try:
            original_path = ws.original_file_path(job.filename)
            findings: List[Finding] = []
            analysis_data: Dict[str, Any] = {}

            # 1. Identification Analyzer
            t_step1 = time.time()
            ident_analyzer = IdentificationAnalyzer()
            ident_res = ident_analyzer.analyze(original_path, job.filename, job.mime_type)
            job.hashes = ident_res.data["hashes"]
            if job.category == "domain":
                job.mime_type = "text/x-domain-intelligence"
                job.signature_description = "Domain & Network Infrastructure Target"
            else:
                findings.extend(ident_res.findings)
                job.mime_type = ident_res.data["detected_mime"]
                job.category = ident_res.data["category"]
                job.signature_description = ident_res.data["description"]

                # Force AppleScript files to be treated as script, never binary
                try:
                    from app.analyzers.applescript_analyzer import AppleScriptAnalyzer
                    if AppleScriptAnalyzer.is_applescript(original_path, job.filename) or AppleScriptAnalyzer.is_applescript(original_path, job.original_filename):
                        job.category = "script"
                        job.mime_type = "application/x-applescript"
                        if not job.signature_description or any(b in job.signature_description for b in ["Binary", "Unknown", "Data", "dosexec", "executable"]):
                            job.signature_description = "AppleScript Script (OSA)"
                except Exception:
                    pass

                # Multi-EVTX Zip detection: if archive contains .evtx files, route to EVTX forensics analyzer
                if job.category == "archive":
                    try:
                        import zipfile
                        with zipfile.ZipFile(original_path, "r") as test_zf:
                            evtx_members = [m for m in test_zf.namelist() if m.lower().endswith(".evtx") and not m.startswith("__MACOSX")]
                            if evtx_members:
                                job.category = "evtx"
                                job.mime_type = "application/x-winevt-archive"
                                job.signature_description = f"Multi-Log Windows Event Archive ({len(evtx_members)} EVTX Logs)"
                    except Exception as ze_chk:
                        logger.debug(f"Zip EVTX detection check: {ze_chk}")
            is_mismatch = ident_res.data["is_mismatch"] if job.category != "domain" else False
            checks_executed.extend(["Cryptographic Hashes (MD5, SHA1, SHA256)", "MIME & Magic Byte Verification"])
            step_timings.append({
                "step": 1,
                "name": "File Identification & Cryptographic Hashing",
                "duration_ms": round((time.time() - t_step1) * 1000, 2),
                "status": "success",
                "details": f"Format: {job.category.upper()} ({job.mime_type})"
            })
            job.progress = 25

            # Fuzzy Hashing & Locality-Sensitive Similarity Clustering
            try:
                from app.analyzers.fuzzy_hasher import FuzzyHasher
                sha256_val = job.hashes.get("sha256", "")
                ssdeep_val = job.hashes.get("ssdeep", "")
                if sha256_val and ssdeep_val:
                    similar_matches = FuzzyHasher.find_similar_samples(sha256_val, ssdeep_val, threshold=35)
                    job.similar_samples = similar_matches
                    checks_executed.append("Fuzzy Hashing (SSDEEP Similarity Clustering)")
                    for sim in similar_matches:
                        if sim.get("similarity", 0) >= 75 and sim.get("risk_level") in ["MALICIOUS", "CRITICAL", "HIGH"]:
                            findings.append(Finding(
                                category="reputation",
                                severity="critical",
                                title=f"Fuzzy Hash Cluster Match: Known Variant ({sim.get('similarity')}% Similarity)",
                                description=(
                                    f"File shares a {sim.get('similarity')}% locality-sensitive/fuzzy hash (SSDEEP) match "
                                    f"with previously analyzed malicious file '{sim.get('filename')}' (Risk: {sim.get('risk_level')}). "
                                    "Strong indication of polymorphic malware mutation or shared code lineage."
                                ),
                                details=sim
                            ))
                            break
            except Exception as fz_err:
                logger.debug(f"Fuzzy hashing similarity check note: {fz_err}")

            # Determine format check key for granular inspection switches
            fmt_key = job.category
            lower_name = (job.filename or "").lower()
            if job.category in ["executable", "binary"]:
                if lower_name.endswith((".elf", ".so")):
                    fmt_key = "elf"
                elif lower_name.endswith((".macho", ".dylib")):
                    fmt_key = "macho"
                else:
                    fmt_key = "executable"
            elif job.category in ["svg", "html"]:
                fmt_key = "svg_html"
            elif lower_name.endswith(".jar") or job.category == "jar":
                fmt_key = "jar"
            elif lower_name.endswith(".crx") or job.category == "extension":
                fmt_key = "extension"
            elif lower_name.endswith((".pcap", ".pcapng", ".cap")) or job.category == "pcap":
                fmt_key = "pcap"
            elif lower_name.endswith((".evtx", ".zip")) and job.category == "evtx":
                fmt_key = "evtx"

            # Record disabled checks for this job's format so UI can hide corresponding data
            disabled_checks = [k for k, v in settings_store.get_format_checks(fmt_key).items() if not v]
            job.disabled_checks = disabled_checks

            # 2. ClamAV Antivirus Scanner
            t_step2 = time.time()
            job.current_step = 2
            job.current_step_label = "Antivirus Engine Inspection (ClamAV)"
            job.progress = 30
            clamav_for_format = settings_store.is_check_enabled(fmt_key, "check_clamav")
            if settings_store.is_global_enabled("clamav_enabled") and clamav_for_format:
                clamav_scanner = ClamAVScanner()
                av_res = clamav_scanner.analyze(original_path, job.filename, job.mime_type)
                findings.extend(av_res.findings)
                job.clamav = av_res.data
                checks_executed.append("ClamAV Antivirus Scanner")
            else:
                job.clamav = None
            step_timings.append({
                "step": 2,
                "name": "Antivirus Engine Inspection (ClamAV)",
                "duration_ms": round((time.time() - t_step2) * 1000, 2),
                "status": "success" if clamav_for_format else "skipped",
                "details": f"ClamAV: {(job.clamav or {}).get('status', 'Skipped')}"
            })
            job.progress = 40

            # 3. Format-specific Analyzers
            t_step3 = time.time()
            job.current_step = 3
            job.current_step_label = "Container Dissection & Structure Verification"
            job.progress = 45
            has_macros = False
            has_javascript = False
            has_path_traversal = False
            is_zip_bomb = False
            has_executable = (job.category == "executable")
            extracted_urls = set()

            if job.category == "pdf":
                pdf_res = PDFAnalyzer().analyze(original_path, job.filename, job.mime_type, provided_password=job.unlock_password)
                findings.extend(pdf_res.findings)
                analysis_data["pdf"] = pdf_res.data
                job.pdf_info = pdf_res.data
                has_javascript = pdf_res.data.get("has_javascript", False)
                job.is_password_protected = pdf_res.data.get("is_password_protected", False)
                job.is_unlocked = pdf_res.data.get("is_unlocked", False)
                if pdf_res.data.get("unlock_password"):
                    job.unlock_password = pdf_res.data.get("unlock_password")
                for u in pdf_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "office":
                office_res = OfficeAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(office_res.findings)
                analysis_data["office"] = office_res.data
                job.office_info = office_res.data
                has_macros = office_res.data.get("has_macros", False)
                for u in office_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "image":
                img_res = ImageAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(img_res.findings)
                analysis_data["image"] = img_res.data
                job.image_info = img_res.data
                for u in img_res.data.get("urls", []):
                    extracted_urls.add(u)

                # AI Image Verification & Provenance (C2PA, diffusion prompts, camera authenticity)
                if "check_ai_provenance" not in job.disabled_checks:
                    try:
                        from app.analyzers.ai_image_verifier import AIImageVerifier
                        ai_ver = AIImageVerifier.verify_image(original_path)
                        job.ai_image_provenance = ai_ver
                        if ai_ver.get("is_ai_generated"):
                            findings.append(Finding(
                                category="provenance",
                                severity="medium" if ai_ver.get("confidence") == "LIKELY_AI" else "high",
                                title=f"Synthetic AI Generated Media Detected ({ai_ver.get('generator_tool', 'AI')})",
                                description=f"Image contains cryptographic C2PA provenance or AI model generation parameters: {', '.join(ai_ver.get('indicators', []))}",
                                details=ai_ver
                            ))
                    except Exception as ai_e:
                        logger.debug(f"AI image verification note: {ai_e}")
                else:
                    job.ai_image_provenance = None

            elif job.category in ["svg", "html"]:
                act_res = ActiveContentAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(act_res.findings)
                analysis_data["active_content"] = act_res.data
                has_javascript = act_res.data.get("has_javascript", False)
                for u in act_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "archive":
                arch_res = ArchiveAnalyzer().analyze(original_path, job.filename, job.mime_type, provided_password=job.unlock_password)
                findings.extend(arch_res.findings)
                analysis_data["archive"] = arch_res.data
                job.archive_info = arch_res.data
                if arch_res.data.get("jar_info"):
                    job.jar_info = arch_res.data["jar_info"]
                has_path_traversal = arch_res.data.get("has_path_traversal", False)
                is_zip_bomb = arch_res.data.get("is_zip_bomb", False)
                has_executable = has_executable or arch_res.data.get("has_executables", False)
                job.is_password_protected = arch_res.data.get("is_encrypted", False)
                job.is_unlocked = arch_res.data.get("is_unlocked", False)
                if arch_res.data.get("unlock_password"):
                    job.unlock_password = arch_res.data.get("unlock_password")

                # Populate embedded files from extracted archive members
                ext_files = arch_res.data.get("extracted_files", [])
                if ext_files:
                    existing_embs = list(getattr(job, "embedded_files", []) or [])
                    job.embedded_files = existing_embs + ext_files

                # Populate extracted text corpus for downstream IOC and URL processing
                text_corp = arch_res.data.get("text_corpus", "")
                if text_corp:
                    job.extracted_code = {"code": text_corp, "language": "text"}
                    for u in re.findall(r'https?://[^\s\'"<>]+', text_corp):
                        extracted_urls.add(u)

            elif job.category == "email":
                email_res = EmailAnalyzer().analyze(original_path, job.filename, job.mime_type, workspace_dir=ws.workspace_dir)
                findings.extend(email_res.findings)
                analysis_data["email"] = email_res.data
                job.email_info = email_res.data
                for u in email_res.data.get("urls", []):
                    extracted_urls.add(u)
                atts = email_res.data.get("attachments", [])
                if atts:
                    job.embedded_files = list(getattr(job, "embedded_files", []) or []) + [
                        {
                            "name": a.get("filename"),
                            "filename": a.get("filename"),
                            "sha256": a.get("sha256"),
                            "md5": a.get("md5"),
                            "size": a.get("size_bytes") or a.get("size") or 0,
                            "mime_type": a.get("content_type"),
                            "is_dangerous": a.get("is_dangerous", False),
                            "source_type": "email_attachment"
                        }
                        for a in atts
                    ]

            elif job.category == "text":
                txt_res = TextAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(txt_res.findings)
                analysis_data["text"] = txt_res.data
                for u in txt_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "domain":
                from app.analyzers.domain_analyzer import DomainAnalyzer
                if not getattr(job, "domain_info", None):
                    job.domain_info = DomainAnalyzer.analyze(job.filename, deep=True)
                for rf in (job.domain_info or {}).get("risk_flags", []):
                    findings.append(Finding(
                        category="reputation",
                        severity=rf.get("severity", "medium").lower(),
                        title=f"Domain Intelligence: {rf.get('title')}",
                        description=rf.get("description", ""),
                        details=rf
                    ))

            elif job.category == "pcap":
                from app.analyzers.pcap_analyzer import PcapAnalyzer
                pcap_res = PcapAnalyzer().analyze(original_path, job.filename, job.mime_type, workspace=ws)
                findings.extend(pcap_res.findings)
                analysis_data["pcap"] = pcap_res.data
                job.pcap_info = pcap_res.data
                for u in pcap_res.data.get("urls", []):
                    extracted_urls.add(u)
                carved = pcap_res.data.get("carved_files", [])
                if carved:
                    job.embedded_files = list(getattr(job, "embedded_files", []) or []) + carved

            elif job.category == "evtx":
                from app.analyzers.evtx_analyzer import EvtxAnalyzer

                def on_evtx_progress(pct: int, label: str):
                    job.progress = min(54, 45 + int(pct * 9 / 100))
                    job.current_step_label = label

                evtx_res = EvtxAnalyzer().analyze(
                    original_path,
                    job.filename,
                    job.mime_type,
                    workspace=ws,
                    progress_callback=on_evtx_progress
                )
                findings.extend(evtx_res.findings)
                analysis_data["evtx"] = evtx_res.data
                job.evtx_info = evtx_res.data

            elif job.category == "lnk":
                from app.analyzers.lnk_analyzer import LnkAnalyzer
                lnk_res = LnkAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(lnk_res.findings)
                analysis_data["lnk"] = lnk_res.data
                job.lnk_info = lnk_res.data
                for u in lnk_res.data.get("urls", []):
                    extracted_urls.add(u)
                if lnk_res.data.get("deobfuscated_payload"):
                    analysis_data["script"] = {
                        "code_modules": [{"name": "LNK Deobfuscated Command", "code": lnk_res.data["deobfuscated_payload"]}],
                        "language": "powershell"
                    }

            # Explicit AppleScript handling
            is_apple = False
            try:
                from app.analyzers.applescript_analyzer import AppleScriptAnalyzer
                is_apple = AppleScriptAnalyzer.is_applescript(original_path, job.filename) or AppleScriptAnalyzer.is_applescript(original_path, job.original_filename)
                if is_apple:
                    job.category = "script"
                    job.mime_type = "application/x-applescript"
            except Exception:
                pass

            if not is_apple and job.category in ["executable", "binary"]:
                exec_res = ExecutableAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(exec_res.findings)
                analysis_data["executable"] = exec_res.data
                job.binary_info = exec_res.data
                if exec_res.data.get("rich_header_hash"):
                    job.hashes["rich_header_hash"] = exec_res.data["rich_header_hash"]
                if exec_res.data.get("imphash"):
                    job.hashes["imphash"] = exec_res.data["imphash"]
                if exec_res.data.get("shellcode"):
                    job.shellcode_info = exec_res.data["shellcode"]
                has_executable = True
                for u in exec_res.data.get("urls", []):
                    extracted_urls.add(u)

            elif job.category == "script" or is_apple:
                from app.analyzers.script_analyzer import ScriptAnalyzer
                script_res = ScriptAnalyzer().analyze(original_path, job.filename, job.mime_type)
                findings.extend(script_res.findings)
                analysis_data["script"] = script_res.data
                job.script_triage = script_res.data
                if script_res.data.get("hta_details"):
                    job.hta_info = script_res.data["hta_details"]
                for u in script_res.data.get("urls", []):
                    extracted_urls.add(u)

                # AppleScript / OSA inspection
                if is_apple:
                    try:
                        from app.analyzers.applescript_analyzer import AppleScriptAnalyzer
                        apple_res = AppleScriptAnalyzer.analyze(original_path, job.filename)
                        job.applescript_info = apple_res
                        job.binary_info = None
                        has_executable = False
                        for af in apple_res.get("findings", []):
                            findings.append(Finding(
                                category="applescript",
                                severity=af.get("severity", "medium").lower(),
                                title=f"AppleScript: {af.get('title')}",
                                description=af.get("description", ""),
                                details=af
                            ))
                        for u in apple_res.get("iocs", {}).get("urls", []):
                            extracted_urls.add(u)
                    except Exception as as_err:
                        logger.debug(f"AppleScript analyzer note: {as_err}")

            # Chrome / Edge Browser Extension Package Triage (.crx / extension zip)
            try:
                from app.analyzers.extension_analyzer import ExtensionAnalyzer
                if ExtensionAnalyzer.is_extension_package(original_path, job.filename):
                    ext_res = ExtensionAnalyzer.analyze(original_path, job.filename)
                    job.extension_info = ext_res
                    for flag in ext_res.get("risk_flags", []):
                        findings.append(Finding(
                            category="extension",
                            severity=flag.get("severity", "medium").lower(),
                            title=f"Browser Extension: {flag.get('title')}",
                            description=flag.get("description", ""),
                            details=flag
                        ))
                    for jf in ext_res.get("js_findings", []):
                        findings.append(Finding(
                            category="extension_code",
                            severity=jf.get("severity", "medium").lower(),
                            title=f"Extension Code: {jf.get('title')}",
                            description=f"File '{jf.get('file')}' contains {jf.get('title')} ({jf.get('occurrences')} occurrence(s)). Snippet: {jf.get('snippet')}",
                            details=jf
                        ))
            except Exception as ext_err:
                logger.debug(f"Extension analyzer note: {ext_err}")


            # Universal Embedded Files & Payload Extraction Engine
            try:
                from app.core.embedded_extractor import UniversalEmbeddedExtractor
                embedded_list = UniversalEmbeddedExtractor.extract_all(
                    file_path=original_path,
                    filename=job.filename,
                    mime_type=job.mime_type,
                    category=job.category,
                    ws=ws,
                    password=job.unlock_password
                )
                existing_embedded = list(getattr(job, "embedded_files", []) or [])
                existing_hashes = {str(x.get("sha256") or x.get("md5") or "").lower() for x in existing_embedded if (x.get("sha256") or x.get("md5"))}
                for ef in (embedded_list or []):
                    ef_hash = str(ef.get("sha256") or ef.get("md5") or "").lower()
                    if not ef_hash or ef_hash not in existing_hashes:
                        existing_embedded.append(ef)
                        if ef_hash:
                            existing_hashes.add(ef_hash)
                job.embedded_files = existing_embedded
                for ef in (embedded_list or []):
                    if ef.get("is_dangerous"):
                        findings.append(Finding(
                            category="structure",
                            severity="critical" if ("Binary" in ef.get("threat_reason", "") or "Executable" in ef.get("threat_reason", "")) else "high",
                            title=f"Dangerous Embedded Payload: '{ef.get('name')}'",
                            description=f"File contains nested payload object '{ef.get('name')}' ({ef.get('mime_type')}, {ef.get('size_formatted')}). {ef.get('threat_reason')}",
                            details=ef
                        ))
                    elif ef.get("source_type") in ["pdf_attachment", "office_embedding"]:
                        findings.append(Finding(
                            category="structure",
                            severity="info",
                            title=f"Embedded File Object: '{ef.get('name')}' ({ef.get('size_formatted')})",
                            description=f"Extracted embedded payload from {ef.get('parent_format')} ({ef.get('origin_stream')}).",
                            details=ef
                        ))
            except Exception as emb_e:
                logger.debug(f"Embedded files extraction note: {emb_e}")

            # Extract active code for modal inspection
            script_code_entry = None
            if analysis_data.get("script", {}).get("code_modules"):
                mods = analysis_data["script"]["code_modules"]
                script_code_entry = {
                    "type": "script",
                    "language": analysis_data["script"].get("script_type", "sh"),
                    "code": mods[0].get("code", "") if mods else "",
                    "modules": mods
                }

            job.extracted_code = (
                script_code_entry
                or analysis_data.get("office", {}).get("extracted_code")
                or analysis_data.get("pdf", {}).get("extracted_code")
                or analysis_data.get("active_content", {}).get("extracted_code")
            )

            step_timings.append({
                "step": 3,
                "name": "Container Dissection & Structure Verification",
                "duration_ms": round((time.time() - t_step3) * 1000, 2),
                "status": "success",
                "details": f"Analyzed {job.category.upper()} structure, extracted {len(getattr(job, 'embedded_files', []) or [])} payload objects"
            })
            checks_executed.append(f"{job.category.upper()} Structure Analysis & Payload Extraction")

            # 4. OCR text and embedded image extraction
            t_step4 = time.time()
            job.current_step = 4
            job.current_step_label = "Optical Character Recognition (OCR) on Visual Content"
            job.progress = 55
            ocr_text = ""
            try:
                ocr_res = OCRAnalyzer.scan_file(original_path, job.category)
                if ocr_res.get("extracted_text"):
                    ocr_text = ocr_res["extracted_text"]
                    for u in ocr_res.get("urls", []):
                        extracted_urls.add(u)
                    findings.append(Finding(
                        category="ocr",
                        severity="info",
                        title=f"OCR Image Text Extracted ({ocr_res.get('images_scanned', 1)} image(s))",
                        description=f"Extracted {len(ocr_text)} characters of text from visual/embedded image pixels.",
                        details={
                            "images_scanned": ocr_res.get("images_scanned", 0),
                            "text_preview": ocr_text[:300],
                            "urls_found": ocr_res.get("urls", [])
                        }
                    ))
                    checks_executed.append(f"OCR Visual Content Scanning ({ocr_res.get('images_scanned', 1)} image(s))")
            except Exception as e:
                logger.debug(f"OCR analysis error: {e}")
                pipeline_errors.append(f"OCR: {e}")

            step_timings.append({
                "step": 4,
                "name": "Optical Character Recognition (OCR) on Visual Content",
                "duration_ms": round((time.time() - t_step4) * 1000, 2),
                "status": "success" if ocr_text else "skipped",
                "details": f"Extracted {len(ocr_text)} characters from visual content" if ocr_text else "No OCR text extracted"
            })

            # 5. YARA Rule Engine Scanning & Threat Intel
            t_step5 = time.time()
            job.current_step = 5
            job.current_step_label = "YARA Pattern Matching & Heuristic Detection"
            job.progress = 65
            yara_for_format = settings_store.is_check_enabled(fmt_key, "check_yara")
            if settings_store.is_global_enabled("yara_enabled") and settings.YARA_ENABLED and yara_for_format:
                try:
                    yara_matches = yara_manager.scan_file(original_path, job.category)
                    job.yara = {
                        "matches_count": len(yara_matches),
                        "matches": yara_matches
                    }
                    checks_executed.append(f"YARA Pattern Matching ({len(yara_matches)} matches)")
                    for ym in yara_matches:
                        findings.append(Finding(
                            category="yara",
                            severity=ym.get("severity", "HIGH").lower(),
                            title=f"YARA Detection: {ym['rule_name']}",
                            description=f"{ym.get('description', '')}. Matched identifier: {ym['identifier']}",
                            details={
                                "rule_id": ym["rule_id"],
                                "target_format": ym["target_format"],
                                "strings": ym.get("strings", [])
                            }
                        ))
                except Exception as e:
                    logger.error(f"YARA scanning failed for job {job_id}: {e}")
            else:
                job.yara = None

            # VirusTotal File Hash Check & Direct Link Generation
            sha256 = job.hashes.get("sha256", "")
            vt_for_format = settings_store.is_check_enabled(fmt_key, "check_virustotal")
            if sha256 and settings_store.is_global_enabled("virustotal_enabled") and vt_for_format:
                vt_res = VirusTotalClient.lookup_file_hash(sha256)
                job.virustotal = vt_res
                checks_executed.append("VirusTotal Hash Intelligence")
                network_lookups_count += 1
                services_contacted.append("VirusTotal")
                if vt_res.get("positives", 0) > 0:
                    findings.append(Finding(
                        category="reputation",
                        severity="critical" if vt_res["positives"] >= 5 else "high",
                        title=f"VirusTotal Detections ({vt_res['positives']}/{vt_res.get('total_engines', 0)} vendors)",
                        description=f"File hash was flagged as malicious or suspicious on VirusTotal by {vt_res['positives']} security vendors.",
                        details={
                            "positives": vt_res["positives"],
                            "total": vt_res.get("total_engines", 0),
                            "web_link": vt_res.get("web_link"),
                            "flagged_engines": vt_res.get("flagged_engines", [])
                        }
                    ))
            else:
                job.virustotal = None

            # CIRCL Hashlookup (NSRL benign check) & ThreatFox Hash Check
            if sha256 and settings_store.is_external_allowed("allow_threat_intel_lookups"):
                try:
                    if settings_store.is_global_enabled("circl_hashlookup_enabled"):
                        from app.analyzers.reputation_client import CirclHashlookupClient
                        circl_res = CirclHashlookupClient.check_hash(sha256)
                        circl_res["search_url"] = f"https://hashlookup.circl.lu/search/{sha256}"
                        job.circl = circl_res
                        checks_executed.append("CIRCL Hashlookup (NSRL)")
                        network_lookups_count += 1
                        services_contacted.append("CIRCL")
                        if circl_res.get("is_nsrl"):
                            findings.append(Finding(
                                category="reputation",
                                severity="info",
                                title=f"CIRCL Hashlookup: Known Benign Software ({circl_res.get('file_name', 'NSRL')})",
                                description=(
                                    f"File SHA-256 matches verified National Software Reference Library (NSRL) database records. "
                                    f"Vendor: {circl_res.get('vendor', 'Standard')}"
                                ),
                                details=circl_res.get("details", {})
                            ))

                    from app.analyzers.reputation_client import ThreatFoxClient
                    tf_hash_res = ThreatFoxClient.check_hash(sha256)
                    tf_hash_res["search_url"] = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{sha256}"
                    job.threatfox = tf_hash_res
                    checks_executed.append("ThreatFox Abuse.ch IOCs")
                    network_lookups_count += 1
                    services_contacted.append("ThreatFox")
                    if tf_hash_res.get("status") == "MALICIOUS":
                        findings.append(Finding(
                            category="reputation",
                            severity="critical",
                            title=f"ThreatFox Malware IOC Hit: {tf_hash_res.get('malware')}",
                            description=f"File hash is recorded in Abuse.ch ThreatFox database as active {tf_hash_res.get('threat_type')}.",
                            details=tf_hash_res
                        ))

                    # Abuse.ch MalwareBazaar Hash Check
                    if settings_store.is_global_enabled("malwarebazaar_enabled"):
                        from app.analyzers.reputation_client import MalwareBazaarClient
                        mb_res = MalwareBazaarClient.check_hash(sha256)
                        job.malwarebazaar = mb_res
                        checks_executed.append("MalwareBazaar Abuse.ch Samples")
                        network_lookups_count += 1
                        services_contacted.append("MalwareBazaar")
                        if mb_res.get("status") == "MALICIOUS":
                            findings.append(Finding(
                                category="reputation",
                                severity="critical",
                                title=f"MalwareBazaar Threat Hit: {mb_res.get('signature', 'Malware')}",
                                description=(
                                    f"File hash is recorded in Abuse.ch MalwareBazaar database. "
                                    f"Signature: {mb_res.get('signature')}, Tags: {', '.join(mb_res.get('tags', []))}. "
                                    f"First seen: {mb_res.get('first_seen', 'N/A')}."
                                ),
                                details=mb_res
                            ))

                    # CrowdStrike Falcon Sandbox / Hybrid Analysis
                    ha_key = settings_store.get_api_key("hybrid_analysis_api_key")
                    ha_enabled = settings_store.is_global_enabled("hybrid_analysis_enabled") or settings_store.is_global_enabled("crowdstrike_enabled")
                    cs_for_format = settings_store.is_check_enabled(fmt_key, "check_crowdstrike")
                    if (ha_enabled or ha_key) and cs_for_format:
                        from app.analyzers.reputation_client import HybridAnalysisClient
                        ha_res = HybridAnalysisClient.check_hash(sha256)
                        job.hybrid_analysis = ha_res
                        checks_executed.append("CrowdStrike Falcon / Hybrid Analysis")
                        network_lookups_count += 1
                        services_contacted.append("CrowdStrike Falcon")
                        if ha_res.get("configured") and ha_res.get("status") in ["MALICIOUS", "SUSPICIOUS"]:
                            findings.append(Finding(
                                category="reputation",
                                severity="critical" if ha_res["status"] == "MALICIOUS" else "high",
                                title=f"CrowdStrike Falcon / Hybrid Analysis: {ha_res.get('verdict', 'Threat Detected').title()} (Score: {ha_res.get('threat_score', 0)}/100)",
                                description=(
                                    f"CrowdStrike Falcon Sandbox community intelligence flagged file hash as {ha_res.get('status')}. "
                                    f"Malware Family: {ha_res.get('malware_family', 'Generic')}."
                                ),
                                details=ha_res
                            ))
                    else:
                        job.hybrid_analysis = None

                    # AlienVault OTX (Open Threat Exchange) Pulse Check
                    from app.analyzers.reputation_client import AlienVaultOTXClient
                    otx_res = AlienVaultOTXClient.check_indicator("FileHash-SHA256", sha256)
                    job.alienvault_otx = otx_res
                    checks_executed.append("AlienVault OTX Pulse Intelligence")
                    network_lookups_count += 1
                    services_contacted.append("AlienVault OTX")
                    if otx_res.get("pulse_count", 0) > 0:
                        pulse_names_str = ", ".join(otx_res.get("pulse_names", [])[:3])
                        tags_str = ", ".join(otx_res.get("tags", [])[:5])
                        findings.append(Finding(
                            category="reputation",
                            severity="critical",
                            title=f"AlienVault OTX Pulse Hit ({otx_res.get('pulse_count')} Threat Pulses)",
                            description=(
                                f"File SHA-256 is tracked in AlienVault Open Threat Exchange pulses. "
                                f"Pulses: {pulse_names_str or 'Threat Intel'}. Tags: {tags_str or 'Malware'}."
                            ),
                            details=otx_res
                        ))
                except Exception as he:
                    logger.debug(f"Extended hash reputation note: {he}")

                if not job.circl and sha256:
                    job.circl = {
                        "configured": True,
                        "status": "NOT_CHECKED" if not settings_store.is_external_allowed("allow_threat_intel_lookups") else "UNKNOWN",
                        "is_nsrl": False,
                        "search_url": f"https://hashlookup.circl.lu/search/{sha256}"
                    }
                if not job.threatfox and sha256:
                    job.threatfox = {
                        "configured": True,
                        "status": "NOT_CHECKED" if not settings_store.is_external_allowed("allow_threat_intel_lookups") else "CLEAN",
                        "search_url": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{sha256}"
                    }
                if not job.malwarebazaar and sha256:
                    job.malwarebazaar = {
                        "configured": True,
                        "status": "NOT_CHECKED" if not settings_store.is_external_allowed("allow_threat_intel_lookups") else "CLEAN",
                        "search_url": f"https://bazaar.abuse.ch/sample/{sha256}/"
                    }
                if not job.alienvault_otx and sha256:
                    otx_key = settings_store.get_api_key("alienvault_otx_api_key") or settings.ALIENVAULT_OTX_API_KEY
                    job.alienvault_otx = {
                        "configured": bool(otx_key),
                        "status": "NOT_CHECKED" if not settings_store.is_external_allowed("allow_threat_intel_lookups") else "CLEAN",
                        "pulse_count": 0,
                        "pulse_names": [],
                        "tags": []
                    }

            job.progress = 72

            step_timings.append({
                "step": 5,
                "name": "YARA Pattern Matching & Threat Intelligence",
                "duration_ms": round((time.time() - t_step5) * 1000, 2),
                "status": "success",
                "details": f"YARA matches: {len((job.yara or {}).get('matches', []))}, External lookups: {network_lookups_count}"
            })

            # 6. URL Analysis & Screenshots
            t_step6 = time.time()
            job.current_step = 6
            job.current_step_label = "URL Extraction & HTTPS Certificate Analysis"
            job.progress = 75
            analyzed_urls = []
            for existing in job.urls:
                if isinstance(existing, dict) and existing.get("url"):
                    extracted_urls.add(existing["url"])

            analysis_data["urls"] = list(extracted_urls)
            target_urls = list(extracted_urls)[:15]

            for idx, url in enumerate(target_urls):  # Analyze up to 15 URLs
                try:
                    url_data = URLAnalyzer.analyze_url(url)
                except Exception as url_err:
                    logger.warning(f"URL analysis skipped for {url!r}: {url_err}")
                    url_data = {
                        "url": url, "domain": "", "protocol": "", "port": None,
                        "is_ssrf_safe": False, "ssrf_reason": f"Unanalyzable URL: {url_err}",
                        "resolved_ips": [], "risk": "LOW RISK",
                        "indicators": ["URL could not be parsed/analyzed"],
                        "reputation": {}, "http_status": None, "redirect_url": None,
                        "is_shortener": False, "target_analysis": None,
                        "tls_valid": False, "certificate": None, "screenshot_available": False,
                    }
                # Attach direct VirusTotal web link for manual inspection
                url_data["vt_web_link"] = VirusTotalClient.get_url_web_link(url)

                # Attempt screenshot for each URL if allowed by policy and SSRF-safe
                if settings_store.is_external_allowed("allow_screenshots") and url_data.get("is_ssrf_safe"):
                    shot_name = f"screenshot_{idx}.png"
                    shot_path = ws.screenshots_dir / shot_name
                    success = ScreenshotClient.capture_screenshot(url, shot_path)
                    # If initial capture failed and a redirect destination was discovered, try destination URL
                    if not success and url_data.get("redirect_url"):
                        success = ScreenshotClient.capture_screenshot(url_data["redirect_url"], shot_path)

                    if success:
                        url_data["screenshot_available"] = True
                        url_data["screenshot_url"] = f"/api/jobs/{job_id}/screenshots/{shot_name}"
                analyzed_urls.append(url_data)
                # Increment progress proportionally during URL inspection & screenshot taking
                job.progress = min(88, 75 + int((idx + 1) / max(len(target_urls), 1) * 13))

            job.urls = analyzed_urls
            job.progress = 88

            if analyzed_urls:
                checks_executed.append(f"URL Forensics & SSL/TLS Verification ({len(analyzed_urls)} URLs)")
                network_lookups_count += len(analyzed_urls)
                services_contacted.append("URL DNS/TLS Probing")

            step_timings.append({
                "step": 6,
                "name": "URL Extraction & HTTPS Certificate Analysis",
                "duration_ms": round((time.time() - t_step6) * 1000, 2),
                "status": "success" if analyzed_urls else "skipped",
                "details": f"Inspected {len(analyzed_urls)} extracted URLs" if analyzed_urls else "No URLs found to inspect"
            })

            # 7. Metadata Consolidation & Threat Watchlist Scanning
            t_step7 = time.time()
            job.current_step = 7
            job.current_step_label = "Metadata & Admin Threat Watchlist Scanning"
            job.progress = 90
            job.metadata = MetadataExtractor.consolidate(
                filename=job.filename,
                file_size=job.file_size,
                mime_type=job.mime_type,
                hashes=job.hashes,
                analysis_data=analysis_data
            )

            # Safe Visual Preview Thumbnail Generation
            try:
                thumb_path = ws.base_dir / "thumbnail.png"
                if thumb_path.exists() and thumb_path.stat().st_size > 0:
                    job.thumbnail_available = True
                    job.thumbnail_url = f"/api/jobs/{job.job_id}/thumbnail"
                elif ThumbnailGenerator.generate_thumbnail(original_path, job.category, thumb_path):
                    job.thumbnail_available = True
                    job.thumbnail_url = f"/api/jobs/{job.job_id}/thumbnail"
            except Exception as e:
                logger.debug(f"Thumbnail generation error: {e}")

            # Admin Warninglist / Watchlist Rule Matching
            try:
                text_corpus_parts = [ocr_text]
                if job.category == "text":
                    text_corpus_parts.append(analysis_data.get("text", {}).get("preview", ""))
                if job.category == "pdf" and analysis_data.get("pdf", {}).get("text"):
                    text_corpus_parts.append(analysis_data["pdf"]["text"])
                if job.category == "email":
                    e_info = analysis_data.get("email", {})
                    text_corpus_parts.append(e_info.get("subject", ""))
                    text_corpus_parts.append(e_info.get("body_plain", ""))
                if job.category == "office" and analysis_data.get("office", {}).get("extracted_text"):
                    text_corpus_parts.append(analysis_data["office"]["extracted_text"])
                if job.category == "script":
                    s_code = analysis_data.get("script", {}).get("source_code") or ""
                    if not s_code and original_path.exists():
                        try:
                            s_code = original_path.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass
                    if s_code:
                        text_corpus_parts.append(s_code)
                if job.extracted_code:
                    text_corpus_parts.append(job.extracted_code.get("code", ""))
                if job.metadata:
                    for fld in job.metadata.general + job.metadata.document + job.metadata.location + job.metadata.camera + job.metadata.embedded:
                        text_corpus_parts.append(fld.value)

                full_corpus = "\n".join(filter(None, text_corpus_parts))
                if full_corpus.strip():
                    wl_findings = WatchlistAnalyzer.scan_text(full_corpus, source_label="file content and metadata")
                    findings.extend(wl_findings)

                # Data Loss Prevention (DLP) & Leaked Credentials Scanner
                try:
                    from app.analyzers.dlp_analyzer import DLPAnalyzer
                    if full_corpus.strip():
                        dlp_findings = DLPAnalyzer.scan_text(full_corpus, source_label="file content and extracted text")
                        findings.extend(dlp_findings)
                except Exception as dlp_err:
                    logger.debug(f"DLP scan error: {dlp_err}")

                # Metadata Forensic Anomaly Findings
                try:
                    if job.metadata and getattr(job.metadata, "forensic_anomalies", None):
                        from app.analyzers.metadata_extractor import detect_metadata_anomalies
                        doc_meta = {}
                        if analysis_data.get("pdf", {}).get("metadata"):
                            doc_meta.update(analysis_data["pdf"]["metadata"])
                        if analysis_data.get("office", {}).get("metadata"):
                            doc_meta.update(analysis_data["office"]["metadata"])
                        if analysis_data.get("image", {}).get("author_info"):
                            doc_meta.update(analysis_data["image"]["author_info"])
                        _, meta_findings = detect_metadata_anomalies(doc_meta)
                        findings.extend(meta_findings)
                except Exception as meta_anom_err:
                    logger.debug(f"Metadata anomalies note: {meta_anom_err}")

                # Automated Deobfuscation & Secondary IOC Extraction
                try:
                    from app.analyzers.deobfuscator import Deobfuscator
                    deobf_corpus = ""
                    if job.extracted_code:
                        deobf_corpus = job.extracted_code.get("code", "")
                    elif full_corpus.strip():
                        deobf_corpus = full_corpus[:50000]

                    if deobf_corpus:
                        deobf_res = Deobfuscator.analyze_payload(deobf_corpus)
                        if deobf_res.get("has_deobfuscated_content"):
                            job.deobfuscation = deobf_res
                            existing_encoded = {
                                f.details.get("encoded_string") or f.details.get("encoded_preview")
                                for f in findings if isinstance(f.details, dict) and (f.details.get("encoded_string") or f.details.get("encoded_preview"))
                            }
                            for b64_item in deobf_res.get("base64_blocks", [])[:5]:
                                if b64_item.get("encoded_full") in existing_encoded or b64_item.get("encoded") in existing_encoded:
                                    continue
                                findings.append(Finding(
                                    category="deobfuscation",
                                    severity="high",
                                    title=f"Identified & Decoded Base64 String ({b64_item.get('encoding', 'Decoded')})",
                                    description=(
                                        f"Identified Base64 string '{b64_item.get('encoded')}'. "
                                        f"Decoded content reveals: {b64_item.get('decoded', '')[:200]}"
                                    ),
                                    details={
                                        "encoded_string": b64_item.get("encoded_full", b64_item.get("encoded")),
                                        "encoded_preview": b64_item.get("encoded"),
                                        "decoded_plaintext": b64_item.get("decoded", ""),
                                        "encoding": b64_item.get("encoding"),
                                        "byte_length": b64_item.get("bytes_len", 0),
                                        "extracted_urls": b64_item.get("extracted_urls", []),
                                        "extracted_ips": b64_item.get("extracted_ips", [])
                                    }
                                ))
                                for u in b64_item.get("extracted_urls", []):
                                    extracted_urls.add(u)

                            for xor_item in deobf_res.get("xor_candidates", [])[:2]:
                                findings.append(Finding(
                                    category="deobfuscation",
                                    severity="critical",
                                    title=f"Decrypted Single-Byte XOR Payload (Key {xor_item.get('key_hex')})",
                                    description=f"Single-byte XOR decryption revealed high-confidence plaintext anchors: {', '.join(xor_item.get('matched_anchors', []))}.",
                                    details=xor_item
                                ))
                                for u in xor_item.get("extracted_urls", []):
                                    extracted_urls.add(u)
                except Exception as deobf_err:
                    logger.debug(f"Deobfuscation pipeline note: {deobf_err}")
            except Exception as e:
                logger.debug(f"Watchlist scan error: {e}")

            # Shannon Entropy & Byte Distribution Analysis
            try:
                from app.analyzers.entropy_analyzer import EntropyAnalyzer
                job.entropy_profile = EntropyAnalyzer.analyze_bytes(file_bytes)
                if job.entropy_profile.get("verdict") == "SUSPICIOUS_HIGH_ENTROPY":
                    findings.append(Finding(
                        category="heuristic",
                        severity="high",
                        title=f"Suspicious High Entropy Payload ({job.entropy_profile.get('overall_entropy')}/8.0)",
                        description=(
                            f"File exhibits high Shannon entropy ({job.entropy_profile.get('overall_entropy')}/8.0) "
                            f"or contains {job.entropy_profile.get('high_entropy_blocks_count')} high-entropy block(s) "
                            f"indicative of packed executables, encrypted droppers, or shellcode."
                        ),
                        details={
                            "overall_entropy": job.entropy_profile.get("overall_entropy"),
                            "high_entropy_blocks": job.entropy_profile.get("high_entropy_blocks_count"),
                            "null_byte_pct": job.entropy_profile.get("null_byte_percentage"),
                            "chi_square": job.entropy_profile.get("chi_square", {}).get("chi_square")
                        }
                    ))
            except Exception as ent_err:
                logger.debug(f"Entropy analysis note: {ent_err}")

            # Anti-Analysis & Evasion Behavior Scanner
            try:
                from app.analyzers.anti_analysis import AntiAnalysisDetector
                anti_analysis_res = AntiAnalysisDetector.scan_all(
                    category=job.category,
                    filename=job.filename,
                    file_bytes=file_bytes,
                    binary_info=job.binary_info,
                    script_triage=job.script_triage,
                    office_info=job.office_info,
                    pdf_info=job.pdf_info,
                    evtx_info=getattr(job, "evtx_info", None),
                    lnk_info=getattr(job, "lnk_info", None)
                )
                job.anti_analysis = anti_analysis_res
                if anti_analysis_res.get("evasion_detected"):
                    for tech in anti_analysis_res.get("techniques", []):
                        findings.append(Finding(
                            category="evasion",
                            severity=tech.get("severity", "high"),
                            title=f"Anti-Analysis Evasion: {tech.get('name')}",
                            description=f"{tech.get('description')} ({tech.get('evidence')}) [MITRE {tech.get('mitre_id', 'T1497')}]",
                            details=tech
                        ))
            except Exception as aa_err:
                logger.debug(f"Anti-analysis scan note: {aa_err}")

            job.progress = 96

            checks_executed.extend(["Metadata Extraction & Forensic Analysis", "DLP & Secret Scanner", "Entropy & Byte Distribution Analysis", "Anti-Analysis & Evasion Detector"])
            step_timings.append({
                "step": 7,
                "name": "Metadata, DLP & Threat Watchlist Scanning",
                "duration_ms": round((time.time() - t_step7) * 1000, 2),
                "status": "success",
                "details": f"Entropy: {(job.entropy_profile or {}).get('overall_entropy', 'N/A')}/8.0, Anomalies: {len(getattr(job.metadata, 'forensic_anomalies', []) or []) if job.metadata else 0}"
            })

            # 8. Computing Explainable Security Risk Score
            t_step8 = time.time()
            job.current_step = 8
            job.current_step_label = "Computing Explainable Security Risk Score"
            job.progress = 98

            # Filter findings based on user-disabled format checks
            findings = [f for f in findings if not is_finding_suppressed(f, job.disabled_checks)]
            job.findings = findings

            # Suppress data objects for disabled checks
            if "check_ai_provenance" in job.disabled_checks:
                job.ai_image_provenance = None
            if "check_anti_analysis" in job.disabled_checks:
                job.anti_analysis = None
            if "check_sections_entropy" in job.disabled_checks:
                job.entropy_profile = None
            if "check_disassembly" in job.disabled_checks and job.binary_info:
                job.binary_info.pop("disassembly", None)
            if "check_tracking_pixels" in job.disabled_checks and job.email_info:
                job.email_info["tracking_pixels"] = []

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

            # Persist analysis data on job model for cross-referencing and entity graphing
            job.analysis_data = analysis_data

            # MITRE ATT&CK Mapping & Attribution
            try:
                from app.analyzers.mitre_attack import MitreAttackMapper
                job.mitre_attack = MitreAttackMapper.map_all(
                    findings=findings,
                    analysis_data=analysis_data,
                    category=job.category
                )
            except Exception as mitre_e:
                logger.debug(f"MITRE ATT&CK mapping note: {mitre_e}")
                job.mitre_attack = []

            # Re-Analysis Threat Intelligence Delta Detection
            try:
                hist = settings_store.get_upload_history()
                sha256 = (job.hashes or {}).get("sha256", "")
                prev_scans = [h for h in hist if h.get("sha256") == sha256 and h.get("job_id") != job.job_id] if sha256 else []
                if prev_scans:
                    prev = prev_scans[0]
                    # VT detection delta
                    prev_vt_score = prev.get("vt_score") or prev.get("vt_ratio") or "0/0"
                    prev_positives = 0
                    try:
                        if "/" in str(prev_vt_score):
                            prev_positives = int(str(prev_vt_score).split("/")[0])
                        elif prev.get("vt_details") and isinstance(prev["vt_details"], dict):
                            prev_positives = int(prev["vt_details"].get("positives", 0))
                    except Exception:
                        pass
                    curr_positives = (job.virustotal or {}).get("positives", 0)
                    new_vt_detections = max(0, curr_positives - prev_positives) if curr_positives > prev_positives else 0

                    # CrowdStrike threat delta
                    prev_cs = prev.get("crowdstrike") or (prev.get("crowdstrike_details") or {}).get("verdict")
                    curr_cs = (job.hybrid_analysis or {}).get("verdict")
                    curr_cs_mal = curr_cs in ["malicious", "suspicious"] or ((job.hybrid_analysis or {}).get("threat_score") or 0) > 50
                    prev_cs_mal = prev_cs in ["malicious", "suspicious"]
                    new_cs_threat = curr_cs_mal and not prev_cs_mal

                    # ClamAV signature delta
                    prev_clam = str(prev.get("clamav") or "").strip().upper()
                    prev_had_sig = prev_clam not in ["", "CLEAN", "OK", "UNKNOWN", "UNAVAILABLE", "DISABLED", "ERROR"]
                    curr_clam_detected = (job.clamav or {}).get("detected", False)
                    curr_clam_sig = (job.clamav or {}).get("malware_name") or "Malware Signature"
                    new_clam_sig = curr_clam_sig if (curr_clam_detected and not prev_had_sig) else None

                    summary_labels = []
                    if new_vt_detections > 0:
                        summary_labels.append(f"+{new_vt_detections} New VirusTotal Detection{'s' if new_vt_detections > 1 else ''}")
                    if new_cs_threat:
                        summary_labels.append("New CrowdStrike Falcon Threat Identified")
                    if new_clam_sig:
                        summary_labels.append(f"New ClamAV Signature: {new_clam_sig}")

                    curr_vt_ratio = f"{(job.virustotal or {}).get('positives', 0)}/{(job.virustotal or {}).get('total_engines', 0)}" if job.virustotal else None

                    job.reanalysis_intel_diff = {
                        "is_reanalysis": True,
                        "previous_scan_date": prev.get("uploaded_at"),
                        "previous_job_id": prev.get("job_id"),
                        "has_new_intelligence": bool(summary_labels),
                        "new_vt_detections": new_vt_detections,
                        "prev_vt_ratio": str(prev_vt_score) if prev_vt_score != "0/0" else None,
                        "curr_vt_ratio": curr_vt_ratio,
                        "new_crowdstrike_threat": new_cs_threat,
                        "crowdstrike_verdict": curr_cs,
                        "new_clamav_signature": new_clam_sig,
                        "summary_labels": summary_labels
                    }
            except Exception as rescan_err:
                logger.debug(f"Re-analysis threat delta calculation note: {rescan_err}")

            # Interactive Entity Relationship Graph Generation
            try:
                from app.core.entity_graph_builder import EntityGraphBuilder
                job.entity_graph = EntityGraphBuilder.build(job)
            except Exception as eg_err:
                logger.debug(f"Entity graph generation note: {eg_err}")

            checks_executed.extend(["Explainable Risk Scoring Engine", "MITRE ATT&CK Behavioral Mapping", "Entity Relationship Graph"])
            step_timings.append({
                "step": 8,
                "name": "Explainable Risk Scoring & Knowledge Graph",
                "duration_ms": round((time.time() - t_step8) * 1000, 2),
                "status": "success",
                "details": f"Score: {job.risk.score}/100 ({job.risk.level}), Graph nodes: {len((job.entity_graph or {}).get('nodes', []))}"
            })

            total_duration_ms = round((time.time() - pipeline_start_time) * 1000, 2)
            job.telemetry = {
                "started_at": datetime.utcfromtimestamp(pipeline_start_time).isoformat() + "Z",
                "completed_at": datetime.utcnow().isoformat() + "Z",
                "total_duration_ms": total_duration_ms,
                "steps": step_timings,
                "checks_executed": list(dict.fromkeys(checks_executed)),
                "disabled_checks": list(job.disabled_checks or []),
                "network_telemetry": {
                    "external_lookups_count": network_lookups_count,
                    "services_contacted": list(dict.fromkeys(services_contacted)),
                    "urls_inspected": len(analyzed_urls)
                },
                "pipeline_errors": pipeline_errors
            }

            # Automated Detection Rule Generation (Sentinel KQL & YARA)
            try:
                from app.analyzers.detection_rules import DetectionRuleGenerator
                job.detection_rules = DetectionRuleGenerator.generate_all(job)
            except Exception as rule_err:
                logger.debug(f"Detection rule generation note: {rule_err}")

            job.state = "ANALYZED"
            job.progress = 100
            job.current_step = 8
            job.current_step_label = "All Pipeline Checks Verified"
            try:
                settings_store.record_file_analysis(
                    category=job.category,
                    risk_level=job.risk.level if job.risk else "CLEAN",
                    findings=findings,
                    file_size=job.file_size
                )
                # VirusTotal details
                vt = job.virustotal or {}
                vt_ratio = None
                if vt.get("positives") is not None and vt.get("total_engines") is not None:
                    vt_ratio = f"{vt['positives']}/{vt['total_engines']}"
                elif vt.get("positives") is not None and vt.get("total") is not None:
                    vt_ratio = f"{vt['positives']}/{vt['total']}"
                elif vt.get("stats"):
                    mal = vt["stats"].get("malicious", 0)
                    total = sum(vt["stats"].values())
                    vt_ratio = f"{mal}/{total}"

                vt_details = None
                if vt:
                    vt_details = {
                        "ratio": vt_ratio,
                        "positives": vt.get("positives", 0),
                        "total_engines": vt.get("total_engines") or vt.get("total", 0),
                        "malicious_count": vt.get("malicious_count", 0),
                        "suspicious_count": vt.get("suspicious_count", 0),
                        "suggested_threat_label": vt.get("suggested_threat_label") or "",
                        "threat_category": vt.get("threat_category") or "",
                        "meaningful_name": vt.get("meaningful_name") or "",
                        "type_description": vt.get("type_description") or "",
                        "tags": vt.get("tags") or [],
                        "web_link": vt.get("web_link") or (f"https://www.virustotal.com/gui/file/{job.hashes.get('sha256', '')}" if job.hashes and job.hashes.get("sha256") else None),
                        "scan_date": vt.get("last_analysis_date") or None,
                        "configured": vt.get("configured", False),
                        "found": vt.get("found", False)
                    }
                elif job.hashes and job.hashes.get("sha256"):
                    vt_details = {
                        "ratio": None,
                        "positives": 0,
                        "total_engines": 0,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "suggested_threat_label": "",
                        "threat_category": "",
                        "meaningful_name": "",
                        "type_description": "",
                        "tags": [],
                        "web_link": f"https://www.virustotal.com/gui/file/{job.hashes.get('sha256')}",
                        "scan_date": None,
                        "configured": False,
                        "found": False
                    }

                # ClamAV details
                clamav_data = job.clamav or {}
                clamav_status = clamav_data.get("status", "CLEAN")
                clamav_result = "CLEAN"
                raw_threat = str(clamav_data.get("threat_name") or clamav_data.get("virus_name") or "").replace('\x00', '').strip()
                if clamav_data.get("infected") or clamav_status == "MALICIOUS":
                    clamav_result = raw_threat or "INFECTED"
                elif clamav_status in ["DISABLED", "ERROR", "UNAVAILABLE"]:
                    clamav_result = clamav_status

                clamav_details = {
                    "status": clamav_status,
                    "result": clamav_result,
                    "threat_name": raw_threat or (clamav_result if clamav_result not in ["CLEAN", "DISABLED", "ERROR", "UNAVAILABLE"] else None),
                    "engine_version": str(clamav_data.get("engine_version") or "N/A").replace('\x00', '').strip(),
                    "signature_db": str(clamav_data.get("signature_db") or "N/A").replace('\x00', '').strip(),
                    "scan_timestamp": clamav_data.get("scan_timestamp") or job.created_at,
                    "error_message": clamav_data.get("error_message") or ""
                }

                # Findings list summary for tooltip
                findings_list = []
                for f in (job.findings or []):
                    findings_list.append({
                        "category": getattr(f, "category", "") or (f.get("category", "") if isinstance(f, dict) else ""),
                        "severity": getattr(f, "severity", "medium") or (f.get("severity", "medium") if isinstance(f, dict) else "medium"),
                        "title": getattr(f, "title", "Finding") or (f.get("title", "Finding") if isinstance(f, dict) else "Finding"),
                        "description": (getattr(f, "description", "") or (f.get("description", "") if isinstance(f, dict) else ""))[:150]
                    })

                # MITRE techniques list summary for tooltip
                mitre_list = []
                for m in (job.mitre_attack or []):
                    tech_id = m.get("technique_id") or m.get("id") or ""
                    tech_name = m.get("technique_name") or m.get("name") or ""
                    tactic = m.get("tactic_name") or m.get("tactic") or ""
                    sev = m.get("severity") or "medium"
                    url = m.get("url") or (f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/" if tech_id else "")
                    mitre_list.append({
                        "id": tech_id,
                        "name": tech_name,
                        "tactic": tactic,
                        "severity": sev,
                        "url": url
                    })

                verdict_str = "Clean"
                if job.risk:
                    verdict_str = getattr(job.risk, "verdict", None) or (job.risk.reasons[0] if getattr(job.risk, "reasons", None) else job.risk.level)

                settings_store.record_upload_history({
                    "job_id": job.job_id,
                    "filename": job.original_filename,
                    "uploaded_at": job.created_at,
                    "category": job.category,
                    "mime_type": job.mime_type,
                    "file_size": job.file_size,
                    "risk_level": job.risk.level if job.risk else "UNKNOWN",
                    "verdict": verdict_str,
                    "sha256": job.hashes.get("sha256", "") if job.hashes else "",
                    "md5": job.hashes.get("md5", "") if job.hashes else "",
                    "ssdeep": job.hashes.get("ssdeep", "") if job.hashes else "",
                    "tlsh": job.hashes.get("tlsh", "") if job.hashes else "",
                    "findings_count": len(job.findings) if job.findings else 0,
                    "findings": findings_list,
                    "vt_score": vt_ratio,
                    "vt_ratio": vt_ratio,
                    "vt_details": vt_details,
                    "clamav": clamav_result,
                    "clamav_details": clamav_details,
                    "crowdstrike": (job.hybrid_analysis or {}).get("verdict"),
                    "crowdstrike_details": job.hybrid_analysis,
                    "mitre_count": len(job.mitre_attack) if job.mitre_attack else 0,
                    "mitre_details": mitre_list,
                })
            except Exception as te:
                logger.error(f"Telemetry record error: {te}", exc_info=True)
            logger.info(f"Completed analysis for Job {job_id}: Risk={job.risk.level if job.risk else 'UNKNOWN'}, Findings={len(findings)}")
            self._save_job_to_disk(job)
            return job

        except Exception as e:
            logger.error(f"Analysis failed for job {job_id}: {e}", exc_info=True)
            job.state = "FAILED"
            job.error_message = str(e)
            try:
                settings_store.record_upload_history({
                    "job_id": job.job_id,
                    "filename": getattr(job, "original_filename", "unknown"),
                    "uploaded_at": getattr(job, "created_at", datetime.utcnow().isoformat() + "Z"),
                    "category": getattr(job, "category", "unknown"),
                    "mime_type": getattr(job, "mime_type", "application/octet-stream"),
                    "file_size": getattr(job, "file_size", 0),
                    "risk_level": "FAILED",
                    "verdict": f"Analysis failed: {e}",
                    "sha256": getattr(job, "hashes", {}).get("sha256", ""),
                    "md5": getattr(job, "hashes", {}).get("md5", ""),
                    "findings_count": len(getattr(job, "findings", [])),
                    "vt_score": None,
                    "clamav": "ERROR",
                    "mitre_count": 0,
                })
            except Exception as he:
                logger.debug(f"Failed upload history record error: {he}")
            self._save_job_to_disk(job)
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

        try:
            # If original file is flagged as active MALWARE, auto-upgrade to maximum disarm
            if job.risk and job.risk.level == "MALICIOUS":
                options.profile = "maximum"
                options.remove_javascript = True
                options.remove_macros = True
                options.remove_embedded_files = True
                options.rasterize_pages = True

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

            job.sanitized_file_path = str(sanitization_res.output_path or output_path)
            job.progress = 60

            # Post-Sanitization Validation
            return self.execute_post_sanitization_validation(job_id)
        except Exception as e:
            logger.error(f"Sanitization failed for job {job_id}: {e}", exc_info=True)
            job.state = "FAILED"
            job.error_message = f"Sanitization error: {str(e)}"
            return job

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

        # Visual & Structural CDR Differencing Engine
        try:
            from app.analyzers.entropy_analyzer import EntropyAnalyzer
            clean_entropy_info = EntropyAnalyzer.analyze_bytes(clean_path.read_bytes())
            clean_entropy = clean_entropy_info.get("overall_entropy", 0.0)
        except Exception:
            clean_entropy = 0.0

        orig_entropy = getattr(job.entropy_profile, "overall_entropy", 0.0) if job.entropy_profile else 0.0
        bytes_reduced = max(0, job.file_size - clean_size)
        pct_reduced = round((bytes_reduced / job.file_size * 100), 1) if job.file_size > 0 else 0.0
        entropy_delta = round(clean_entropy - orig_entropy, 3)

        modifications = []
        if orig_macros:
            modifications.append({
                "element": "VBA / Office Macros",
                "action": "Stripped",
                "severity": "critical",
                "description": "All executable macro code modules & VBA streams purged"
            })
        if orig_js:
            modifications.append({
                "element": "JavaScript & Actions",
                "action": "Neutralized",
                "severity": "high",
                "description": "Interactive scripts, OpenAction, and Launch dictionaries pruned"
            })
        if orig_meta_count > clean_meta_fields:
            modifications.append({
                "element": "Metadata & Privacy Attributes",
                "action": "Sanitized",
                "severity": "medium",
                "description": f"Reduced from {orig_meta_count} to {clean_meta_fields} fields"
            })
        if orig_urls_count > clean_urls_count:
            modifications.append({
                "element": "External Hyperlinks & Callouts",
                "action": "Defanged",
                "severity": "low",
                "description": f"Removed {orig_urls_count - clean_urls_count} external links"
            })
        if orig_att and clean_att_count == 0:
            modifications.append({
                "element": "Embedded Objects & Attachments",
                "action": "Extracted & Detached",
                "severity": "high",
                "description": "Nested payload attachments safely detached from document"
            })

        cdr_diff = {
            "original_file": {
                "filename": job.original_filename,
                "size_bytes": job.file_size,
                "entropy": orig_entropy,
                "metadata_fields": orig_meta_count,
                "sha256": job.hashes.get("sha256", "")
            },
            "sanitized_file": {
                "filename": clean_path.name,
                "size_bytes": clean_size,
                "entropy": clean_entropy,
                "metadata_fields": clean_meta_fields,
                "sha256": clean_hashes.get("sha256", "")
            },
            "metrics": {
                "bytes_reduced": bytes_reduced,
                "reduction_percentage": pct_reduced,
                "entropy_delta": entropy_delta,
                "threats_neutralized": len([f for f in job.findings if f.severity in ["critical", "high"]]),
                "structural_modifications_count": len(modifications)
            },
            "structural_modifications": modifications,
            "actions_taken": getattr(job.sanitization_result, "actions_taken", None) or getattr(job.sanitization_result, "removed_items", []),
            "removed_items": getattr(job.sanitization_result, "removed_items", []),
            "warnings": getattr(job.sanitization_result, "warnings", [])
        }

        job.cdr_diff = cdr_diff
        validation_data["cdr_diff"] = cdr_diff
        job.validation = validation_data
        job.state = "COMPLETED"
        job.progress = 100
        try:
            target_fmt = "pdf" if (job.sanitization_options and job.sanitization_options.convert_to_pdf) else ("png" if (job.sanitization_options and job.sanitization_options.convert_to_png) else "original")
            settings_store.record_file_sanitization(target_fmt)
        except Exception as te:
            logger.debug(f"Sanitization telemetry record error: {te}")
        logger.info(f"Post-sanitization validation completed for Job {job_id}: is_clean={validation_data['is_clean']}")
        self._save_job_to_disk(job)
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
        elif category == "email":
            return EmailSanitizer()
        elif category == "text":
            return TextSanitizer()
        elif category == "script":
            from app.sanitizers.script_sanitizer import ScriptSanitizer
            return ScriptSanitizer()
        elif category in ["executable", "binary"]:
            return ExecutableSanitizer()
        return None


    def unlock_and_reanalyze(self, job_id: str, password: str) -> JobModel:
        job = self.get_job(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        job.unlock_password = password
        job.is_password_protected = True
        job.state = "QUEUED"
        job.progress = 0
        job.error_message = None
        return self.execute_analysis_pipeline(job_id)

job_manager = JobManager()
