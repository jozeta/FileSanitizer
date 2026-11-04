# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

FileSanitizer is a self-hosted malware-triage and Content Disarm & Reconstruction (CDR) platform:
upload a file, it is identified, analysed (ClamAV, YARA, MITRE mapping, deep format-specific
triage for Office/PDF/PE/ELF/APK/Java/LNK/EVTX/PCAP/email/images, URL and domain/IP
intelligence), risk-scored with explanations, then sanitized into a new clean file and re-scanned.
Python 3.11 FastAPI backend + Celery, React 19 + TypeScript + Vite frontend, all in Docker
Compose.

## Commands

```sh
cp .env.example .env
docker compose up -d --build
docker compose ps && curl http://localhost:8010/api/health

docker compose exec api pytest tests/ -v          # backend tests
cd frontend && npm run build                       # frontend type-check + build (tsc && vite build)
cd frontend && npm run dev                         # frontend dev server
```

UI: http://localhost (or :8080). API docs: http://localhost:8010/docs (host port 8010; inside Docker
the API listens on 8000, which nginx proxies to).

## Layout

| Path | Contents |
|---|---|
| `backend/app/main.py`, `config.py` | FastAPI app and settings (from env) |
| `backend/app/api/` | REST endpoints |
| `backend/app/analyzers/` | Per-format and per-technique analysis modules |
| `backend/app/sanitizers/` | CDR / sanitization profiles |
| `backend/app/network/` | URL/domain/IP intelligence, SSRF guard, Nmap/Subfinder/dnsx |
| `backend/app/workers/` | Celery tasks |
| `backend/app/core/` | Shared plumbing |
| `backend/tests/` | pytest suite (`pytest.ini`) |
| `frontend/src/` | React app (`components/`, `api/`, `context/`, `types/`, `utils/`, `version.ts`) |
| `browser/` | Isolated Playwright service for sandboxed URL screenshots |
| `test-files/` | Benign and **deliberately malicious-looking** samples for testing |
| `scripts/`, `scratch/` | One-off generators and verification scripts |

Services: `frontend` (nginx), `api`, `worker`, `redis`, `clamav`, `browser`.

## Security invariants (don't regress these)

- The uploaded original is never modified; every job gets a random UUID workspace
  (`/jobs/<job-id>/`). File paths are never built from user input.
- Every outbound connection to a discovered URL/host goes through the SSRF guard, which blocks
  RFC 1918, loopback, link-local, cloud metadata (169.254.169.254) and Docker networks.
- Containers run as non-root with `cap_drop: [ALL]` and `no-new-privileges`; only the
  scanner containers add the specific capabilities Nmap needs.
- Risk verdicts must include concrete reasons, not just a score.
- Active scanning (Nmap etc.) is for targets the operator is authorized to scan.

## Notes

- API keys for external intel (VirusTotal, AbuseIPDB, …) go in `.env` only (it is gitignored);
  `.env.example` must hold placeholders only.
- `test-files/` contents can trip antivirus on a dev machine. That's expected; don't "fix" them.
- Bump `frontend/src/version.ts` and the README release badge together when releasing.
