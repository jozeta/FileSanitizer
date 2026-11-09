# Changelog

All notable changes to FileSanitizer are listed here, newest first.

Releases follow the project's git tags. Entries were reconstructed from the commit history.

## [Unreleased]

- Accessibility:
  - the footer disclaimer now meets WCAG AA contrast (slate-400 → slate-500 at 11px), and the
    upload prompt is an `<h2>` under the page `<h1>` instead of an `<h3>`, fixing the skipped
    heading level on the landing page
  - the header nav no longer forces page-level horizontal scrolling on small screens; it shrinks
    and scrolls within its own bounds (WCAG 1.4.10 reflow)
  - the analysis splash status is a polite live region (`role="status"`), so screen readers
    announce when analysis starts and completes
  - decorative icons in the header, upload panel and app chrome are now `aria-hidden`, so screen
    readers no longer announce them as unlabeled graphics (icon-only controls keep their labels)
- Security hardening from the 2026-10 audit, each guarded by a regression test in
  `backend/tests/test_audit_regressions.py`:
  - the IP/domain forensic tool runner no longer builds shell command strings (`shell=True`
    removed); indicators are validated against an allowlist and commands run as argv lists, closing
    the unauthenticated command-injection path
  - the backend image no longer installs `sudo` or grants passwordless `sudo nmap`, removing the
    container-root privilege-escalation leg
  - CORS uses an explicit origin allowlist instead of `*` with credentials
  - in production the admin JWT secret is generated randomly when the shipped placeholder value is
    detected, and admin login compares credentials in constant time
  - email / HTML / SVG identification precedence was fixed so an email whose body starts with
    markup is still classified as an email (previously it was mis-typed as HTML/SVG and its active
    content skipped the email sanitizer)
- Animations and transitions respect the system's "Reduce motion" setting
- Lint clean-up: removed 270 unused imports and the names of 49 unused variables (every call made
  for its effect is kept); `ruff.toml` now enforces unused imports/variables. Backend suite: 311 passed
- ruff (`ruff.toml`: syntax errors, undefined names and other pyflakes errors) with a CI lint job.
  It found real bugs, now fixed:
  - the byte-level analyses (entropy profile, anti-analysis detection) never ran: `file_bytes` was
    undefined, and the error was swallowed. They now get the uploaded file's bytes
  - reading a job's file for entity extraction always failed (`os` not imported)
  - an HTML parse error in the active-content analyzer crashed its own error handler (`logger`)
  - a failed email-to-PDF conversion crashed its fallback (`warnings` undefined); the warning is
    now returned with the .eml result
  - the entity graph added a second node for a subdomain already shown by the domain-intel
    attack-surface scan when the text also mentioned it; it now enriches the existing node
  - duplicate keys in the extension analyzer's result; `not in` style
- Sysmon event 25 (ProcessTampering: process hollowing, herpaderping) is now **critical** by default,
  like 8 (CreateRemoteThread) and 10 (ProcessAccess). It was listed twice, and the later "info" entry
  won. Saved settings that list 25 explicitly keep their own value
- The API is published on host port 8010 instead of 8000 (Ratatosk uses 8000), so both can run at
  once; inside Docker it still listens on 8000. The Vite dev proxy and the API docs follow
- Self-host the Inter and JetBrains Mono fonts (no more Google Fonts requests); the nginx CSP no
  longer allows fonts.googleapis.com / fonts.gstatic.com
- Ignore macOS, Claude Code and secret files; add MIT license
- Add CLAUDE.md with project guidance for Claude Code
- Add CI workflow, Dependabot config, security policy

## [2.7.0] - 2026-10-23

- Initial commit of FileSanitizer platform
- Add comprehensive security test files suite
- feat: extract URLs from document body and metadata, add test files with embedded links
- feat: add URL file fetcher with SSRF/watchlist checks, How It Works guide, and supported formats matrix
- feat: enterprise multi-artifact security analysis, forensic timelines, correlation engine & modern UI
- feat: add malicious-pdf test suite and Dockerfile from jonaslejon/malicious-pdf
- feat(pdf): interactive Didier Stevens PDFiD token & stream inspector and full malicious PDF exploit suite detections
- feat(analyzers): add deep CVE and malicious behavior detections across all supported formats
- Organize test-files into demo_showcase and correlated_investigation suites
- chore: remove duplicate unnumbered files in correlated_investigation folder
- feat(correlation): intertwine all 7 attack investigation artifacts with shared hashes, telemetry, and IOCs
- feat(forensics): elevate correlated investigation suite to ultra-realistic authenticity
- feat(decompiler): enrich implant binary with authentic x86 instructions, CFG branches, loops, and call hierarchy
- feat(cross-artifact): add interactive clickable cross-file navigation across all triage views and correlation mapping
- Enrich EVTX telemetry, fix terminal replay playback, and enhance threat graph grouping, proximity, and multi-selection
- fix(react): resolve minified error #310 by moving all hooks before conditional returns
- feat(graph): upgrade All Entities filter toggle behavior and bring Threat Graph controls to Entity Graph
- fix(graph): preserve true entity styling for shared nodes, add SHARED badge tag, and update Shared Only filter
- Enrich archive relationships, member forensics, and cross-artifact Threat Graph correlation
- Add Select Connected Nodes button to entity inspector in Threat Graph and Entity Graph
- feat(graph,timeline): add 'Show empty nodes' filter and consecutive similar activities grouping
- fix(graph): add showEmptyNodes to useMemo deps, guarantee empty nodes visibility and robust VT/CrowdStrike clean node extraction
- feat(threat-graph): default to sample layout and far proximity, exclude files from select-connected, support cmd/ctrl/shift multi-selection toggle
- feat(threat-graph): add file inclusion filtering and restore missing metadata node in entity graph
- feat(threat-graph): select only visible connected nodes and deselect ttps, vulns, and artifacts by default
- feat: enable sending embedded files to analysis as new workspace jobs and link already analyzed files
- feat(settings): add function in settings to toggle Telemetry & Diagnostics tab with hidden by default
- feat(domain-intel): add host discovery, passive exposure, IOC quick-enrichment, cross-platform build fix, and version tracking (v2.1.0)
- feat(v2.2.2): parallelize domain intel, fix Windows CRLF auth, add rotating security slogans, and resilient web archive mirrors
- perf(v2.2.3): optimize SSRF and threat watchlist checks with decoupled background pipelines
- Switch active port scanning to Nmap with SYN stealth scans, service versioning, and bump version to v2.2.4
- Update README.md with Nmap active reconnaissance, smart pivots, attack surface mapping, and bump version to v2.2.5
- feat: extract and visualize emails, domains, watchlist keywords, ips, hostnames, usernames, and names in entity and threat graphs (v2.2.6)
- feat: add operator node hide and solid circle highlight with color picker to entity and threat graphs (v2.2.7)
- docs: update README with operator node visibility controls, dynamic slogans, and bump to v2.2.8
- feat: Add Android APK & Java file forensic security analysis and CDR (v2.3.0)
- feat(apk): add client filesize check, deep APK technical analysis, and forensic dashboard
- feat(mobile-java): MobSF-inspired malicious API catalog, network security config audit, and deep JAR bytecode forensics
- fix(apk): resolve anti-analysis evasion, multi-DEX bomb, ZIP corruptions, v2/v3 certs, and eliminate DAD decompilation hang
- feat(apk): add live CTI, Play Store authenticity, packer detection, malware signatures, and keystore audit
- fix(apk): resolve empty and lacking tabs across APK analysis forensics
- feat(java): implement STRRAT case study forensics and 4-pillar JAR behavioral analysis
- feat: forensic checklist suites, test file audit fixes, cloud provider signatures, and clean triage UI
- feat(security): v2.4.2 security hardening, command injection fix, and auth isolation
- feat: Shodan CTI integration and automated Google Dorks sensitive file engine (v2.5.0)
- feat: interactive entity enclosure boxes, subnet hierarchy, and external CTI caching (v2.6.0)
- feat: integrate Subfinder and dnsx reconnaissance pipeline, entity graph hierarchy, and URL explorer deep-dive
- feat(ui): display Subfinder overview banner and highlight Attack Surface sub-tab
- feat: run Subfinder and dnsx reconnaissance in background with live animation and polling
- perf: optimize UI responsiveness, code-split triage bundles, and eliminate blocking alerts
- chore(release): bump version to 2.7.0
