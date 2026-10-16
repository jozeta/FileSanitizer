# FileSanitizer — Security & Functional Audit Report

**Date:** 2026-10-17
**Target:** FileSanitizer v2.4.0 — running at `http://localhost:8080/` (frontend), API `http://localhost:8000/`
**Scope:** Source at `/Users/zeta/Desktop/code/FileSanitizer/`, live Docker deployment (`filesanitizer-*` containers), supplied corpus in `test-files/`.
**Method:** Repo recon → static review → live dynamic testing against the running API → independent verification. The original `test-files/` corpus was **not** modified. All proof-of-concept actions wrote benign marker files only, inside the ephemeral container, and were cleaned up.

---

## A. Executive summary

FileSanitizer is a large, feature-rich FastAPI + React malware/CDR/domain-intel platform (60+ analyzers/sanitizers, ~78k LoC backend). Core detection primitives work well: file identification, hashing (independently verified correct), ClamAV, YARA, and the email/PCAP/APK/PE analyzers produce accurate, evidence-backed findings on the real corpus.

**However, the deployment is critically insecure.** The single most severe issue is an **unauthenticated remote code execution** chain that yields **root inside the API/worker container**, reachable by uploading one crafted file to a public endpoint. Authentication on the admin surface is effectively absent (hardcoded, shipped JWT secret + default `admin/admin`), and the entire job/analysis surface has no authorization at all.

| Metric | Count |
|---|---|
| Confirmed security vulnerabilities (reproduced) | 6 |
| Confirmed functional / detection defects | 3 |
| Probable / needs-more-evidence (hypotheses) | 2 |
| Informational | 2 |
| Feature areas test-exercised | identification, hashing, ClamAV, YARA, email, SVG/HTML, domain/IP intel, SSRF guard, auth, CORS, job API |

**Highest-risk findings (P0):**
- **FS-SEC-001** — Unauthenticated OS command injection → container-root RCE (domain/IP "offline tools" run `shell=True` with attacker-controlled target, and `appuser` has passwordless `sudo nmap` → root).
- **FS-SEC-002** — Admin auth bypass: JWT signing key is the hardcoded default shipped in `.env`; admin JWTs are forgeable offline. Default creds `admin/admin` also active.
- **FS-SEC-003** — No authorization on `/api/jobs/*` and `GET /api/files`: any unauthenticated client enumerates and reads every user's uploads and full analysis.

**Critical limitations on confidence:**
- The full `pytest` suite could not be run end-to-end: locally the venv lacks `dnspython` (collection error); in-container the whole-suite run is SIGKILLed (heavy parallel imports). Individual test files pass (43 passed across the first 6 files before the loop was killed). Detection-quality metrics (precision/recall) were therefore **not** computed across the whole corpus — the corpus is unlabeled and too small/biased for defensible rates.
- SSRF residual issues (TOCTOU/rebinding, per-analyzer connections) are **code-confirmed** but not dynamically exploited (would require controlled DNS).
- The stored-XSS concern (FS-SEC-006) is **Probable**, not confirmed: payload delivery was blocked by an unrelated misclassification bug (FS-DET-001) and the sanitizer stripped all vectors on the real sample.

---

## B. Feature verification matrix (key features)

| Feature | Implementation | Test performed | Expected | Actual | Status | Evidence |
|---|---|---|---|---|---|---|
| File identification (magic bytes) | `app/analyzers/identification.py` | Upload EICAR, APK, EML | Correct MIME/category | Correct for most; `.eml` w/ `<html>`/`<svg>` in first 512B → misclassified | PARTIAL | FS-DET-001 |
| SHA-256 hashing | `identification.calculate_hashes` | Upload EICAR, compare `shasum` | Match | `275a021b…fd0f` matches exactly | PASS | hash compare |
| ClamAV scan | `core/clamav_manager.py` | Upload EICAR | MALICIOUS / Eicar sig | `Eicar-Test-Signature`, ClamAV 1.5.4 | PASS | /analysis |
| Reputation enrichment (Hybrid Analysis) | `analyzers/reputation_client.py` | EICAR hash lookup | Real verdict only if key set | Real live hit (key persisted); correct | PASS | live query |
| Email forensics | `analyzers/email_analyzer.py` | Real phishing `.eml` | SPF/DKIM/BEC/typosquat | Correct, rich findings | PASS | /analysis |
| Email HTML preview | `frontend/.../EmailTriageCard.tsx:849` | Payload emails | Safe render | Regex/BS4 sanitize, no DOMPurify | PARTIAL | FS-SEC-006 |
| Domain/IP intel | `analyzers/domain_analyzer.py`, `ip_domain_forensics.py` | `.domain` upload | Intel, no code exec | Executes `shell=True` CLI tools | FAIL | FS-SEC-001 |
| URL fetch SSRF guard | `network/ssrf.py`, `url_fetcher.py` | localhost / 169.254.169.254 / file:// | Blocked | All blocked at entry | PASS (entry) | curl tests |
| SSRF (post-resolution / analyzers) | `tls_inspector.py`, `domain_analyzer.py`, `active_recon.py` | Code review | Re-validate per connect | No re-validation; TOCTOU | FAIL | FS-SEC-005 |
| Admin login / JWT | `core/settings_store.py`, `api/settings.py` | Forge token w/ default key | Reject forged | Accepted; full admin | FAIL | FS-SEC-002 |
| Job data authz | `api/jobs.py`, `api/files.py` | Unauth GET job/list | 401 | 200, full data | FAIL | FS-SEC-003 |
| CORS | `app/main.py` | Preflight w/ evil Origin | Restrict | Reflects Origin + credentials | FAIL | FS-SEC-004 |
| Archive bomb / traversal safety | `analyzers/archive_analyzer.py` | Existing tests | Safe | `test_archive_safety.py` 2 passed | PASS | pytest |
| Path traversal (workspace) | `core/file_isolation.py` | Code review | `assert_within_workspace` | Enforced on file paths | PASS | code |
| API docs exposure | `app/main.py` (FastAPI) | GET /docs, /openapi.json | Off in prod | 200 in `APP_ENV=production` | FAIL | FS-INFO-001 |

---

## C. Individual findings

### FS-SEC-001 — Unauthenticated OS command injection → container-root RCE
- **Category:** Security vulnerability · **Severity:** Critical · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected feature:** Domain/IP "Offline Tools CLI" live execution
- **Affected files:** `app/analyzers/ip_domain_forensics.py` (`_execute_cli_tool`, `generate_ip_domain_offline_tools_guide`); reachable via `app/api/files.py:upload_files` → `core/job_manager.py:execute_analysis_pipeline` (domain branch ~L605) → `analyzers/domain_analyzer.py:analyze`. Privesc: `backend/Dockerfile` sudoers rule.
- **Code references:**
  - `ip_domain_forensics.py:1446-1448` `subprocess.run(f"dig {target} ... dig -x {primary_ip or target} ...", shell=True, ...)`
  - `:1507` `openssl s_client -connect {target}:443 -servername {target} ...` with `shell=True`
  - `:1545` `python3 -c "...'{ip_val}'..."` with `shell=True`
  - `Dockerfile`: `echo "appuser ALL=(ALL) NOPASSWD: /usr/bin/nmap" > /etc/sudoers.d/appuser`
- **Description:** When a job is categorized `domain`, the pipeline runs a suite of "offline" CLI tools. Several are built by f-string interpolation of the target indicator into a shell string executed with `shell=True`. The target originates from the uploaded filename/content and is only stripped of `[<>\s!]` (`job_manager.py` / `domain_analyzer.py`), which does **not** remove `;`, `|`, `&`, `$()`, backticks, or newlines. A crafted indicator injects arbitrary shell commands. The process runs as `appuser`, which has passwordless `sudo /usr/bin/nmap`; `sudo nmap --script <nse>` executes `os.execute()` as **root** inside the container.
- **Expected:** Indicators are passed as argv (never a shell string) and strictly validated; no passwordless root sudo.
- **Actual:** Arbitrary command execution as `appuser`, escalatable to container root.
- **Reproduction:**
  1. `printf '{"target":"example.invalid;id>/tmp/fsaudit_poc_ip;#","network":{"ip":"$(id>/tmp/fsaudit_poc_ip)"}}' > poc.domain`
  2. `curl -F "files=@poc.domain" http://localhost:8000/api/files` (no auth)
  3. Poll job → `ANALYZED`.
- **Evidence:** `/tmp/fsaudit_poc_ip` created in container containing `uid=1001(appuser) gid=1001(appgroup)`. Privesc verified: `sudo -n nmap --script fsaudit.nse -sn localhost` ran `os.execute` producing a root-owned marker containing `uid=0(root) gid=0(root)`.
- **Root cause:** `shell=True` + interpolated untrusted target; insufficient sanitization; passwordless root sudo for nmap.
- **Impact:** Full unauthenticated RCE as container root; the API container holds `NET_RAW/NET_ADMIN/AUDIT_WRITE` and sits on both networks (pivot to redis/clamav/browser). Malware-analysis platforms are prime targets; this turns a file upload into host-adjacent compromise.
- **Exploitability:** No auth, no special prerequisites, single HTTP request. **CVSS 4.0: 9.3 (Critical)** — `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` (assumptions: network-reachable deployment; container boundary = scope change).
- **Recommended fix:** Eliminate `shell=True`; pass argv lists only (`["dig", target, "A", ...]`). Validate the indicator against a strict allowlist regex (`^[A-Za-z0-9.:_-]+$` for host/IP) before any use and reject otherwise. Remove the nmap sudoers rule; rely on the file capability already set (`setcap cap_net_raw...`), or drop live nmap entirely. Prefer the pure-Python fallbacks already present (dnspython, `ipaddress`) over shelling out.
- **Regression test:** Upload a `.domain` with `;`, `$()`, backticks, newline in target; assert (a) no marker/side-effect file, (b) indicator rejected or passed literally as argv. Unit test `_execute_cli_tool` asserting it never calls `subprocess.run` with `shell=True`.
- **Dependencies/side effects:** Behavior-preserving if argv refactor keeps tool output parsing.

### FS-SEC-002 — Forgeable admin JWT (hardcoded shipped secret) + default credentials
- **Category:** Security vulnerability · **Severity:** Critical · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `app/config.py` (`ADMIN_SECRET_KEY`, `ADMIN_PASSWORD` defaults), `.env` (ships identical values), `core/settings_store.py:create_admin_token/verify_admin_token/verify_admin_login`.
- **Code references:** `config.py`: `ADMIN_SECRET_KEY = "filesanitizer-jwt-secret-key-32byte-minimum-secure-2026"`, `ADMIN_PASSWORD = "admin"`. `settings_store.py:1843` `jwt.encode(payload, settings.ADMIN_SECRET_KEY, HS256)`.
- **Description:** The HS256 signing key is a constant baked into source and shipped verbatim in `.env` (and `.env.example`). Anyone with the public code can mint a valid `{"role":"admin"}` token offline. Independently, `admin/admin` works.
- **Reproduction:** Forge `{"sub":"admin","role":"admin","exp":...}` signed with the known key.
- **Evidence:** Forged token → `GET /api/settings/verify` returns `{"valid":true,"username":"admin"}`; `GET /api/settings` returns full config. `POST /api/settings/login {"username":"admin","password":"admin"}` returns a valid token.
- **Impact:** Complete admin takeover: edit YARA/warninglist/CDR policies, flip `external-policy` to disable SSRF/external controls, read audit logs, manage API keys. Chains with FS-SEC-001/005.
- **Exploitability:** Trivial, unauthenticated. **CVSS 4.0: 9.3 (Critical)**.
- **Recommended fix:** Require `ADMIN_SECRET_KEY`/`ADMIN_PASSWORD` to be set with no usable default — fail startup if unset or equal to the known placeholder. Generate a random secret per deployment. Ship `.env.example` with empty/placeholder values and keep real `.env` out of distribution. Hash the admin password (store a hash, not plaintext compare).
- **Regression test:** Startup aborts when `ADMIN_SECRET_KEY` is the placeholder/empty; token signed with the old default is rejected.

### FS-SEC-003 — Missing authorization on all job endpoints and job listing
- **Category:** Security vulnerability · **Severity:** High · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `app/api/jobs.py` (no `Depends(require_admin)` on any route), `app/api/files.py:list_all_jobs` (`GET /api/files`), upload/fetch/investigate routes.
- **Description:** Every `/api/jobs/{id}/*` route and `GET /api/files` is unauthenticated. `GET /api/files` returns all job IDs + filenames + risk levels; `GET /api/jobs/{id}/analysis|download|report|raw-content|...` then return full content. Job IDs are uuid4 (not guessable) but the listing hands them out.
- **Evidence:** `GET /api/files` → 15 jobs incl. `trojan.exe`, `01_phishing_email.msg`, `deep.internal.api.banking-secure.org`; `GET /api/jobs/<id>/analysis` → 200 full analysis, unauthenticated.
- **Impact:** Any network client reads every uploaded sample's analysis (and can download originals/sanitized output), triggers re-analysis, active-recon (nmap), deobfuscation, and deletes jobs. Multi-user/data-confidentiality breach for a tool that ingests malware and sensitive documents.
- **Exploitability:** Unauthenticated. **CVSS 4.0: ~8.2 (High)**.
- **Recommended fix:** Apply an auth dependency to the jobs router and `GET /api/files` (session/token), or bind jobs to an authenticated owner and scope reads to the owner. At minimum, remove the unauthenticated global listing.
- **Regression test:** Each jobs route returns 401 without a valid token; a token for user A cannot read user B's job.

### FS-SEC-004 — Reflective CORS with credentials
- **Category:** Security vulnerability · **Severity:** Medium · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `app/main.py` — `CORSMiddleware(allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])`.
- **Evidence:** `OPTIONS /api/files` with `Origin: https://evil.example` → `access-control-allow-origin: https://evil.example`, `access-control-allow-credentials: true`.
- **Impact:** Any website can make credentialed cross-origin calls. Because the job API has no auth (FS-SEC-003), a victim visiting a malicious page can have their browser enumerate/read local FileSanitizer data and trigger analysis/recon. Starlette reflects the Origin when credentials are enabled, so `*` effectively becomes "any origin."
- **Recommended fix:** Set an explicit allowlist of trusted origins; do not combine wildcard with `allow_credentials=True`. If the API is token-in-header (not cookies), set `allow_credentials=False` and a tight origin list.
- **Regression test:** Preflight from a non-allowlisted origin omits `access-control-allow-origin`.

### FS-SEC-005 — SSRF: TOCTOU/DNS-rebinding and unvalidated per-analyzer connections
- **Category:** Security vulnerability · **Severity:** High · **Confidence:** Code-confirmed · **Status:** Code-confirmed (not dynamically exploited)
- **Affected files:** `network/url_fetcher.py` (validate then `httpx.Client` re-resolves), `network/tls_inspector.py:334/343/552` (`socket.create_connection((host,port))` on user host), `analyzers/domain_analyzer.py:205/1094/1259/...` (`httpx.Client` to target), `network/active_recon.py` (nmap/connect to target), `analyzers/ip_domain_forensics.py` curl/openssl to `{target}`.
- **Description:** The entry guard `validate_url_for_ssrf` resolves DNS and checks the IP, but the subsequent connection re-resolves independently (classic TOCTOU / DNS rebinding) and many analyzers connect to the user-supplied host **without any SSRF check at all**. A domain that resolves to a public IP at validation and an internal IP at connect (or simply a hostname only ever used by `tls_inspector`/`domain_analyzer`) reaches internal services, cloud metadata, etc.
- **Evidence:** Direct localhost/metadata/`file://` are correctly blocked at `fetch-url` (verified). Residual paths are code-level: `is_ip_blocked`/`validate_url_for_ssrf` appears only in `url_fetcher`, `active_recon`, `active_security_prober`, `web_fingerprinter`, `web_exposure`, `url_analyzer` — **not** in `tls_inspector.py`, `domain_analyzer.py`, `advanced_dns.py`, `passive_dns.py`, `threat_intelligence.py`, etc. (grep tally in audit log).
- **Impact:** Internal network/metadata access, port scanning of internal hosts via the domain-intel path (worsened by no auth).
- **Recommended fix:** Centralize egress through a pinned-IP HTTP/socket client: resolve once, verify the IP, then connect to that exact IP (host header/SNI preserved), re-checking on every redirect. Route all analyzer HTTP/socket calls through it. Block non-public IPs at the socket layer.
- **Regression test:** Mock a resolver returning public-then-private; assert connection refused. Assert each network module calls the pinned client.

### FS-SEC-006 — Potential stored XSS in email HTML preview (regex/BS4 sanitizer, no DOMPurify)
- **Category:** Security vulnerability · **Severity:** High (if confirmed) · **Confidence:** Probable · **Status:** Not reproduced (delivery blocked by FS-DET-001)
- **Affected files:** `frontend/src/components/EmailTriageCard.tsx:849` (`dangerouslySetInnerHTML`), `app/analyzers/email_analyzer.py:_clean_and_inspect_html` (produces `body_html_sanitized`).
- **Description:** The analyst-facing preview renders backend-sanitized email HTML via `dangerouslySetInnerHTML`; the frontend only rewrites `href`s. Sanitization is server-side BeautifulSoup (`html.parser`): it `decompose()`s script/iframe/object/embed/form/meta/applet/base, deletes `on*` attributes, and neutralizes `javascript:`/`data:text/html` in href/src/action. No DOMPurify or allowlist serializer is used. `html.parser` + manual mutation is a known mutation-XSS (mXSS) class; foreign-content/`<style>`/`<template>`/namespace tricks can reintroduce executable markup on re-serialization. On the real sample all vectors were correctly stripped.
- **Why not confirmed:** Test payloads could not be delivered to the email path — any `.eml` whose first 512 bytes contain `<svg`/`<html` is misclassified (FS-DET-001), so the email sanitizer never ran on them. The one well-formed sample was fully sanitized.
- **Recommended fix:** Sanitize with an allowlist library (DOMPurify client-side on render, and/or `bleach`/`nh3` server-side) rather than denylist regex/attribute deletion. Render the preview inside a sandboxed `<iframe sandbox>` with `srcdoc`, not `dangerouslySetInnerHTML`.
- **Regression test:** Feed a battery of mXSS/polyglot payloads through `_clean_and_inspect_html`; assert no `on*`, `<script>`, `javascript:`, or namespace-reintroduced handlers survive; snapshot DOMPurify output.

### FS-DET-001 — `.eml`/`.msg` misclassified as HTML/SVG → email forensics bypass
- **Category:** Detection accuracy · **Severity:** Medium (evasion) · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `app/analyzers/identification.py` — `detect_file_type` calls `inspect_text_type(header)` **before** `inspect_email_type(...)`; `inspect_text_type` (L272-282) substring-matches `<svg`/`<html` anywhere in the first 512 bytes.
- **Description:** Because text/markup detection runs first and uses substring matching on a 512-byte window, any email whose first 512 bytes contain `<html` or `<svg` (short headers, HTML-first body, or an inline SVG — all common in phishing) is classified as `html`/`svg`. The `.eml` extension short-circuit in `inspect_email_type` is never reached, so **all** email forensics (SPF/DKIM/DMARC, BEC, typosquat, attachment triage, thread-hijacking) are skipped.
- **Reproduction:** Multipart `.eml` with an HTML part containing `<html>`/`<svg>` within the first 512 bytes → `GET /analysis` shows `category: html` (or `svg`), `email_info: null`. The real `phishing_credential_alert.eml` (HTML part >512B in) correctly classifies as `email`.
- **Evidence:** `xss4.eml` (multipart, `.eml`) → `category: html`; `xss3.eml` (inline `<svg>`) → `category: svg`; real sample → `category: email` with full findings.
- **Impact:** Trivial analysis/detection evasion for malicious email; also a general precedence bug (markup substrings override container types).
- **Recommended fix:** Check `inspect_email_type` (extension + RFC822 header heuristics) **before** `inspect_text_type`. Make `inspect_text_type` anchor on document start (`snippet.startswith`) and require markup to be the leading content, not a substring. Short-circuit on known extensions.
- **Regression test:** `.eml`/`.msg` with `<html>`/`<svg>` in the first 512 bytes classify as `email`; fixtures for both multipart and single-part.

### FS-DET-002 — Hybrid Analysis tags mislabeled as MITRE ATT&CK technique IDs
- **Category:** Detection accuracy · **Severity:** Low · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `app/analyzers/reputation_client.py` (`mitre_attck` built from `top.get("mitre_attcks") or top.get("tags")`, mapping arbitrary tags via `str(m)`).
- **Evidence:** EICAR HA lookup produced `mitre_attck: ['tag','viruscheck','eicar','scan','1105825','xss-test','test','agenttesla']` — free-text tags presented as ATT&CK technique IDs.
- **Impact:** Misleading ATT&CK attribution in reports/Navigator.
- **Recommended fix:** Only map entries that match an ATT&CK ID pattern (`T\d{4}(\.\d{3})?`); keep other tags in a separate "tags" field.

### FS-FUNC-001 — Test suite not runnable end-to-end (collection crash / OOM-style kill)
- **Category:** Functional / maintainability · **Severity:** Medium · **Confidence:** Confirmed · **Status:** Reproduced
- **Affected files:** `backend/tests/` + runtime deps.
- **Evidence:** Local `.venv` run fails collection with `ModuleNotFoundError: No module named 'dns'` across 17 test modules (venv lacks `dnspython`). In-container whole-suite `pytest tests` is SIGKILLed (137). Running files individually: `test_7_features_suite` 5✓, `test_advanced_features` 9✓, `test_apk_and_java_analysis` 14✓, `test_archive_safety` 2✓, `test_body_and_metadata_urls` 6✓, `test_deobfuscator_stix_and_community_packs` 7✓ — then the loop was killed on the next network/subprocess-heavy module.
- **Impact:** No reliable CI signal; regressions (including the above) go uncaught. Live-network/subprocess calls inside unit tests cause flakiness and resource spikes.
- **Recommended fix:** Pin test deps (incl. `dnspython`) in a test requirements file; mark network/subprocess tests and mock external calls by default; run with `-p no:cacheprovider` and bounded parallelism; add a `pytest-timeout`-style guard. Provide a documented `make test` that passes in the container.
- **Regression test:** CI job runs the full suite green within a memory/time budget.

### FS-INFO-001 — API docs/OpenAPI exposed in production
- **Category:** Security (info disclosure) · **Severity:** Low/Informational · **Confidence:** Confirmed · **Status:** Reproduced
- **Evidence:** `GET /docs` and `GET /openapi.json` → 200 with `APP_ENV=production`, `DEBUG=false`.
- **Recommended fix:** Disable `docs_url`/`openapi_url` when `APP_ENV=production` (or gate behind admin auth).

### FS-INFO-002 — Verbose error echoes exception text to clients
- **Category:** Security (info disclosure) · **Severity:** Informational · **Confidence:** Code-confirmed
- **Affected files:** `app/api/files.py:fetch-url/investigate-ioc` — `HTTPException(500, detail=f"Failed to fetch remote file: {e}")`.
- **Recommended fix:** Log the exception server-side; return a generic client message.

---

## D. Prioritization

| Priority | Findings | Rationale |
|---|---|---|
| **P0 — Critical** | FS-SEC-001, FS-SEC-002, FS-SEC-003 | Unauthenticated RCE-to-root; trivial admin takeover; full data exposure. Contain immediately (take the deployment off any reachable network until fixed). |
| **P1 — High** | FS-SEC-005, FS-SEC-006, FS-SEC-004 | SSRF to internal/metadata; probable analyst-side stored XSS; reflective CORS amplifies the no-auth API. |
| **P2 — Medium** | FS-DET-001, FS-FUNC-001 | Email-analysis evasion; no CI safety net. |
| **P3 — Low** | FS-DET-002, FS-INFO-001, FS-INFO-002 | Accuracy/labeling and info disclosure. |

---

## E. AI coding-agent implementation backlog

See `security_audit_backlog.json` for the machine-readable version. Tasks are independent unless an ordering constraint is noted.

1. **TASK-001 (FS-SEC-001)** — Remove `shell=True`; argv-only subprocess; strict indicator allowlist; drop passwordless `sudo nmap`. *DoD:* command-injection regression test passes; no `shell=True` in `ip_domain_forensics.py`/`active_recon.py`; sudoers rule removed from `Dockerfile`.
2. **TASK-002 (FS-SEC-002)** — Fail startup on default/empty `ADMIN_SECRET_KEY`/`ADMIN_PASSWORD`; random per-deploy secret; hash password; scrub `.env` of real secrets. *DoD:* forged-token test rejected; startup abort test passes.
3. **TASK-003 (FS-SEC-003)** — Auth dependency on jobs router + `GET /api/files`; owner-scoped reads. *DoD:* all routes 401 without token; cross-user read denied. *Depends on TASK-002 (auth must be trustworthy first).* 
4. **TASK-004 (FS-SEC-004)** — Explicit CORS origin allowlist; drop wildcard+credentials. *DoD:* non-allowlisted origin gets no ACAO header.
5. **TASK-005 (FS-SEC-005)** — Central pinned-IP egress client; route all analyzer network calls through it; re-validate on redirect. *DoD:* rebinding mock test blocks connect; grep shows no raw `httpx`/`socket.create_connection` to user hosts outside the client.
6. **TASK-006 (FS-SEC-006)** — Allowlist sanitizer (nh3/bleach server-side + DOMPurify client-side) and/or sandboxed iframe preview. *DoD:* mXSS payload battery produces no executable markup. *Depends on TASK-007 so payloads reach the email path in tests.*
7. **TASK-007 (FS-DET-001)** — Reorder identification: email/container detection before markup substring sniffing; anchor markup detection at document start. *DoD:* `.eml` with leading `<html>`/`<svg>` classifies as `email`.
8. **TASK-008 (FS-FUNC-001)** — Test deps pinned; network/subprocess mocked/marked; bounded, timed CI run. *DoD:* full suite green in CI.
9. **TASK-009 (FS-DET-002)** — Filter `mitre_attck` to valid ATT&CK ID regex. *DoD:* non-ATT&CK tags excluded from the ATT&CK field.
10. **TASK-010 (FS-INFO-001/002)** — Gate `/docs`/`/openapi.json` in prod; generic error messages. *DoD:* docs 404 in prod; no exception text in responses.

---

## Audit log (commands/tools, abbreviated)
- Recon: `git status`, `docker ps`, `docker-compose.yml`, `.env` (keys only), route enumeration via grep.
- Static: grep for `shell=True`/`subprocess`/`httpx`/`socket`/`dangerouslySetInnerHTML`; SSRF call-site tally; identification precedence read.
- Dynamic: EICAR upload (hash vs `shasum -a 256`, ClamAV), `.domain` command-injection PoC (benign marker), `sudo nmap --script` root PoC (benign marker, cleaned), forged-JWT vs `/api/settings*`, `admin/admin` login, unauth `GET /api/files` + `/analysis`, CORS preflight, SSRF localhost/metadata/`file://`, email XSS/misclassification probes.
- Tests: per-file `pytest` in container (43 passed across 6 files before kill); whole-suite SIGKILL noted.
- Corpus preserved; all PoC artifacts were benign marker files inside the ephemeral container and were removed.
