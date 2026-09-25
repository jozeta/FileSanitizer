# FileSanitizer

> **"Don't trust the file. Wash it first."**

FileSanitizer is a modern, security-focused web application and API platform for **file sanitization, malware analysis, metadata removal, and Content Disarm and Reconstruction (CDR)**.

Designed as a self-hosted Docker application, FileSanitizer allows users to upload untrusted files, inspect them across deep static and behavioral analyzers, review explainable risk reports, disarm potential exploit payloads, and download verified clean reconstructions.

---

## 1. Overview & Architecture

```text
UPLOAD
   ↓
FILE IDENTIFICATION (Magic-byte detection, cryptographic MD5/SHA-1/SHA-256)
   ↓
SECURITY ANALYSIS
   ├── ClamAV Antivirus Scanner (Isolated daemon)
   ├── File Structure & Parser Exploit Analysis
   ├── Metadata Extraction (EXIF, GPS, XMP, IPTC, Author)
   ├── Embedded Object & OLE Storage Detection
   ├── Macro Detection (VBA, AutoOpen hooks, ActiveX)
   ├── JavaScript Detection (PDF, HTML, SVG)
   ├── URL Extraction & SSRF-Protected Analysis
   └── Pluggable URL Reputation & Screenshot Sandbox
   ↓
EXPLAINABLE RISK EVALUATION (Clean / Low Risk / Medium Risk / High Risk / Malicious)
   ↓
USER SELECTS SANITIZATION OPTIONS (Minimal / Privacy / Security / Maximum CDR)
   ↓
SANITIZATION & CONTENT DISARM AND RECONSTRUCTION (CDR)
   ↓
POST-SANITIZATION VALIDATION (Full pipeline re-scan & verification)
   ↓
CLEAN FILE READY FOR DOWNLOAD
```

### Key Security Principles

* **The original uploaded file is never overwritten.** All transformations produce a new file in an isolated workspace.
* **Non-Root & Principle of Least Privilege:** Application containers run as unprivileged users (`appuser`, `pwuser`), drop all Linux capabilities (`cap_drop: [ALL]`), and enforce `no-new-privileges:true`.
* **Zero Host Path Traversal:** File paths are never derived from user input. Each upload receives a cryptographically random UUID workspace (`/jobs/<job-id>/`).
* **Strict SSRF Defense:** Any discovered URL is validated through an IP resolution firewall before connection. Private ranges (RFC 1918), loopback, link-local, cloud metadata (`169.254.169.254`), and Docker internal networks are blocked.
* **Explainable Risk Engine:** Security classifications always include specific, actionable reasons and explicit disclaimers rather than opaque numerical scores.

---

## 2. Supported File Formats & Capabilities

| Format Group | Formats | Security Analysis | Sanitization & CDR Capabilities |
| :--- | :--- | :--- | :--- |
| **Documents (PDF)** | PDF, PDF/A | JavaScript, OpenAction, Launch actions, AcroForms, XFA dynamic forms, attachments, embedded streams, incremental updates, URLs | **Selective Disarm:** Remove metadata, annotations, JS, attachments, links.<br>**Maximum CDR:** Full-page pixel rasterization (pages → images → clean PDF). |
| **Office Documents** | DOCX, XLSX, PPTX, DOC, XLS, PPT, RTF, ODT, ODS, ODP | VBA Macros (`MACROS DETECTED`), ActiveX controls, OLE objects, external relationships (`attachedTemplate` injection), DDE formulas, revisions, comments | **Structural CDR:** Strip VBA macros (`vbaProject.bin`), purge ActiveX/OLE, neutralize external relationship targets, clear tracked changes and metadata. |
| **Images** | JPEG, PNG, GIF, TIFF, BMP, WEBP | EXIF tags, GPS physical coordinates, camera serial numbers, author/artist tags, ICC profiles, XMP packets, text comments | **Privacy & Disarm:** Strip EXIF/GPS/XMP, re-encode pixel data, flatten alpha transparency onto solid white, format conversion (PNG/JPG). |
| **Active Vector Graphics** | SVG | `<script>` elements, inline DOM event handlers (`onload`, `onclick`), `javascript:` URIs, external resource imports, XML entities (XXE) | **Safe XML Disarm:** Strip script elements and handlers.<br>**Safest CDR:** Rasterize SVG to clean PNG. |
| **Web & Markup** | HTML, HTM | JavaScript blocks, external `<script src>`, `<iframe>`, interactive forms, event handlers, meta refresh redirects, embedded plugins | **HTML Disarm:** Strip scripts, iframes, and forms.<br>Neutralize external hyperlinks. |
| **Archives** | ZIP, 7Z, TAR, GZIP | Recursive safe inspection without blind extraction: path traversal (`../`), zip bombs (ratio & size limits), executables (`.exe`, `.bat`, `.ps1`), password protection | **Safe Member Repack:** Exclude traversal entries, strip executable binaries, package clean archive. |
| **Plain Text & Data** | TXT, CSV, JSON, XML, YAML, Markdown | Character encoding analysis (UTF-8, UTF-16, BOM), CSV formula injection (DDE execution attacks) | **Text Sanitizer:** Strip BOM, sanitize DDE formula prefixes (`=`, `+`, `-`, `@`), strip control characters. |

---

## 3. Installation & Docker Deployment

### Prerequisites

* [Docker](https://docs.docker.com/get-docker/) (v24.0 or newer)
* [Docker Compose](https://docs.docker.com/compose/) (v2.20 or newer)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/example/FileSanitizer.git
   cd FileSanitizer
   ```

2. Configure environment:
   ```bash
   cp .env.example .env
   ```

3. Launch all services with Docker Compose:
   ```bash
   docker compose up -d
   ```

4. Access the web interface:
   * **Web UI:** [http://localhost](http://localhost) (or [http://localhost:8080](http://localhost:8080))
   * **API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
   * **Health Endpoint:** [http://localhost:8000/api/health](http://localhost:8000/api/health)

---

## 4. Configuration Reference

All settings can be configured via environment variables or the `.env` file:

```env
# Application Settings
APP_NAME=FileSanitizer
APP_ENV=production
DEBUG=false
API_PREFIX=/api

# Storage & Privacy Retention
JOBS_DIR=/jobs
MAX_FILE_SIZE_MB=100
FILE_RETENTION_MINUTES=30
CLEANUP_INTERVAL_SECONDS=300

# Archive Processing Safety Quotas
MAX_ARCHIVE_FILES=10000
MAX_ARCHIVE_SIZE_MB=500
MAX_RECURSION_DEPTH=5
MAX_PROCESSING_TIME=300

# ClamAV Antivirus Daemon
CLAMAV_ENABLED=true
CLAMAV_HOST=clamav
CLAMAV_PORT=3310
CLAMAV_TIMEOUT=30

# Optional URL Reputation Providers
VIRUSTOTAL_ENABLED=false
VIRUSTOTAL_API_KEY=your_virustotal_api_key

SAFE_BROWSING_ENABLED=false
SAFE_BROWSING_API_KEY=your_google_safe_browsing_key

URLHAUS_ENABLED=false
URLHAUS_API_KEY=your_urlhaus_api_key

# Sandboxed Playwright Screenshot Service
SCREENSHOT_ENABLED=true
BROWSER_SERVICE_URL=http://browser:3000/screenshot
SCREENSHOT_TIMEOUT=15

# Redis Broker
REDIS_URL=redis://redis:6379/0
```

---

## 5. Antivirus & Security Engines Setup

### ClamAV Integration

FileSanitizer connects to ClamAV over a local TCP stream socket (`INSTREAM` protocol).

* In Docker Compose, the `clamav` container initializes automatically and updates its signature database in the background via `freshclam`.
* The API dynamically displays engine version and database signature date.
* **Malware Quarantine Policy:** If ClamAV flags a file as `MALICIOUS`, FileSanitizer prevents downloading the original file and displays a critical warning.

### Optional URL Reputation Feeds

To enable external threat intelligence feeds for discovered URLs:

1. **VirusTotal:** Set `VIRUSTOTAL_ENABLED=true` and provide `VIRUSTOTAL_API_KEY`.
2. **URLhaus (Abuse.ch):** Set `URLHAUS_ENABLED=true` and provide `URLHAUS_API_KEY`.
3. **Google Safe Browsing:** Set `SAFE_BROWSING_ENABLED=true` and provide `SAFE_BROWSING_API_KEY`.

*(Note: API keys are securely held on the backend and never exposed to the frontend browser).*

---

## 6. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/files` | Upload one or multiple files. Queues asynchronous analysis. |
| `GET` | `/api/files` | List active jobs in workspace. |
| `GET` | `/api/jobs/{id}` | Get job state, progress percentage, and summary. |
| `GET` | `/api/jobs/{id}/analysis` | Get complete findings, risk evaluation, hashes, and AV scan. |
| `GET` | `/api/jobs/{id}/metadata` | Get structured metadata grouped by category with sensitivity tags. |
| `GET` | `/api/jobs/{id}/urls` | Get extracted URLs, domain reputation, and screenshot metadata. |
| `GET` | `/api/jobs/{id}/screenshots/{file}` | Retrieve sandboxed website screenshot preview. |
| `POST` | `/api/jobs/{id}/sanitize` | Trigger sanitization and CDR with chosen profile or custom options. |
| `GET` | `/api/jobs/{id}/result` | Get post-sanitization validation and before/after comparison. |
| `GET` | `/api/jobs/{id}/download` | Download the sanitized clean file. |
| `GET` | `/api/jobs/{id}/report` | Download structured security audit report in JSON. |
| `DELETE` | `/api/jobs/{id}` | Immediately purge workspace and temporary artifacts. |
| `GET` | `/api/health` | Service health check and scanner connectivity diagnostics. |

---

## 7. Data Retention & Privacy

FileSanitizer operates on zero persistent storage for user content:

* **Automatic Workspace Purge:** An internal daemon runs every `CLEANUP_INTERVAL_SECONDS` and deletes all files belonging to jobs older than `FILE_RETENTION_MINUTES` (default: 30 minutes).
* **Manual Immediate Purge:** Users can clear workspace data immediately by deleting the job or resetting the session.
* **No Content Logging:** File contents and sensitive metadata fields are never written to application logs.

---

## 8. Local Development & Automated Testing

### Backend Unit & Integration Tests

Run the test suite using pytest:

```bash
# Activate virtual environment
source .venv/bin/activate

# Execute all tests
cd backend
pytest -v
```

The automated test suite verifies:
* Binary magic byte detection & MIME spoofing defense
* Path traversal and null-byte filename sanitization
* SSRF validation (blocking cloud metadata, private subnets, loopback)
* PDF JavaScript detection and page rasterization CDR
* Office VBA macro detection, relationship inspection, and macro removal
* Image EXIF metadata stripping and alpha flattening
* Archive zip bomb detection and executable filtering
* SVG script extraction and vector-to-PNG rasterization
* Complete end-to-end integration pipeline (Upload → Analyze → Sanitize → Validate → Download)

### Frontend Build & Linting

```bash
cd frontend
npm install
npm run build
```

---

## 9. Known Limitations & Disclaimers

> **Important Security Notice:**
> FileSanitizer performs automated security analysis and file sanitization. A **"CLEAN"** result means that no malicious content was detected by the configured analysis engines; **it does not constitute an absolute guarantee that a file is completely safe.**
>
> Sanitization significantly reduces risk but cannot guarantee that every conceivable malicious payload or parser vulnerability has been neutralized.

* **PDF Rasterization Trade-offs:** The "Maximum Sanitization" profile rasterizes all pages into image layers. While this guarantees the complete eradication of active JavaScript and malicious stream exploits, the resulting document will not contain selectable or searchable text.
* **Password-Protected Files:** Files encrypted with unknown passwords cannot be inspected by static scanners without the decryption key.
