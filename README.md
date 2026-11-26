# Bug Hunter Lab

> **Don't just detect. Prove. Fix. Verify.**

An evidence-first, non-destructive web vulnerability assessment platform built for authorized security testing.

---

## Problem Statement & Solution

Many lightweight web scanners either emit unverified alerts without raw HTTP evidence or run invasive payloads unsafe for staging and educational environments.

**Bug Hunter Lab** validates every user-supplied HTTP/HTTPS target against SSRF, DNS-rebinding, and open-redirect hazards before a single packet leaves the server, executes four scoped non-destructive inspection modules, records raw observations alongside severity and confidence rationales in SQLite, and exports multi-page PDF reports from persisted scan records.

---

## Key Features & Four Security Checks

### Implemented Features
- **Dynamic Target Validation & SSRF Gate (`POST /api/targets/validate`)**:
  - Normalizes HTTP/HTTPS URLs, trims whitespace, rejects embedded credentials, obfuscated IPs (integer/octal/hex/shorthand), `localhost`, loopback, RFC 1918 private networks, link-local metadata (`169.254.169.254`), multicast, reserved, and non-global IPv4/IPv6 ranges.
  - Resolves DNS before connection and rejects targets if **any** resolved record is prohibited.
  - Enforces a standard port policy (`80` for HTTP, `443` for HTTPS unless explicitly configured via `BHL_EXTRA_ALLOWED_PORTS`).
  - Pins TCP connections directly to the pre-validated IP (`sni_hostname` preserves TLS SNI/certificate validation) and re-validates every redirect hop (`GET`/`HEAD` only, max redirects, loop detection, timeouts, and response-size caps).
- **Four Real Security Inspection Modules (`POST /api/scans`)**:
  1. **HTTP Header Inspector**: Checks `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options` (plus CSP `frame-ancestors`), `X-Content-Type-Options`, and `Referrer-Policy` for missing and weak directives.
  2. **Cookie Security Analyzer**: Parses multiple `Set-Cookie` headers independently for `Secure`, `HttpOnly`, and `SameSite`, redacts all raw cookie values (`name=[REDACTED]`), and reports `Not applicable` when no cookies are issued.
  3. **Exposed Path Inspector**: Probes `/robots.txt`, `/.well-known/security.txt`, `/sitemap.xml`, `/.env`, `/.git/HEAD`, `/config.json`, `/backup/`, and `/server-status` against a randomized non-existent baseline path to filter out soft-404/SPA HTTP 200 fallbacks and mark ambiguous responses `Inconclusive`.
  4. **Safe Injection Inspector**: Sends harmless `GET` baseline and comparison probes (`bhlprobe7391`, `bhlprobe7391'`, `bhlprobe7391<>`), separating benign/unencoded input reflection from database error signatures and flagging static/unparameterized endpoints as `Inconclusive`.
- **SQLite Persistence & Evidence UI**:
  - Persists real scans, per-module `checkResults` (`finding_detected`, `no_issue_observed`, `inconclusive`, `not_applicable`, `scan_failed`), and findings in SQLite (`GET /api/scans`, `GET /api/findings`).
  - Displays Dashboard metrics, Scan Results & Module Observations, Evidence Log with inline expandable HTTP captures, Case Records, and client-side multi-page A4 PDF export (`jsPDF`).

### Planned / Incomplete Features (Not Yet Implemented)
- **Backend ReportLab PDF Export Endpoint** (currently PDF export is generated client-side in the browser via `jsPDF` from persisted SQLite scan data).
- **Automated Full-Scan Comparison & Verification Rescan** (comparing two scans of the same target to classify persistent, newly detected, and *not observed in this rescan* findings).

---

## Technology Stack

- **Frontend**: React 18, TypeScript, Vite 6, Tailwind CSS v4, React Router, Lucide Icons, `jsPDF`
- **Backend**: Python 3, FastAPI, Uvicorn, HTTPX (`httpcore` IP-pinning & SNI), Pydantic, SQLite (`sqlite3`)
- **Testing**: Python `unittest` (with `httpx.MockTransport` & mocked DNS), Node `node:test`

---

## System Architecture & Workflow

```text
User enters URL + Authorization Confirmation (React UI)
  │
  ▼
POST /api/targets/validate (FastAPI)
  ├── URL normalization, scheme/credential/port checks
  ├── DNS resolution & IPv4/IPv6 SSRF blocklist
  └── Rejects prohibited targets (400/403) without creating scan records
  │
  ▼
POST /api/scans (Unified Scan Orchestrator)
  ├── SafeHttpClient (GET/HEAD only, IP-pinned TLS SNI, redirect re-validation, size/timeout caps)
  ├── Module A: HTTP Header Inspector
  ├── Module B: Cookie Security Analyzer
  ├── Module C: Exposed Path Inspector (vs random non-existent baseline)
  └── Module D: Safe Injection Inspector (non-destructive GET probes)
  │
  ▼
SQLite Persistence (scans + findings + per-module observations)
  │
  ▼
Frontend Views (Investigation HQ, Scan Results, Evidence Log, Case Records, PDF Export)
```

---

## Installation & Setup

### Prerequisites
- **Python**: 3.11+ (tested on Python 3.14)
- **Node.js**: 20+ and `npm`

### 1. Install Backend Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Install Frontend Dependencies
```bash
npm install
```

### 3. Configure Environment (Optional)
Copy `.env.example` to `.env` if you need custom ports, CORS origins, timeouts, or database path:
```bash
cp .env.example .env
```

---

## Running Frontend & Backend

Open **two terminals** at the repository root:

### Terminal 1 — FastAPI Backend
```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

### Terminal 2 — React Frontend
```bash
npm run dev
```
*(On Windows PowerShell if `npm.ps1` execution is restricted, use `npm.cmd run dev`.)*

Open `http://127.0.0.1:5173` in your browser. Vite proxies `/api/*` requests to `http://127.0.0.1:8000`.

---

## Performing an Authorized Scan

1. Confirm the top-right status pill shows **`API online`**.
2. Go to **New investigation** (`/scan/new`).
3. Enter an authorized `http://` or `https://` URL you own or have explicit written permission to test.
4. Check the **Authorization confirmation** box and click **Validate Target** to inspect the backend's normalized URL, resolved IPs, or rejection reason.
5. Select the desired security checks and click **Start scan**.
6. Inspect per-module statuses, observed headers/cookies/paths, expandable HTTP evidence, and export the **PDF report** from **Case records** (`/reports`).

---

## Running Verification Tests

```bash
# Backend unit & scanner tests (target validation, SafeHttpClient, SQLite history, all 4 scanners)
python -m unittest discover -s backend/tests -v

# Frontend TypeScript check & production build
npm run build
```

---

## Known Limitations & Responsible-Use Disclaimer

- **Authorized Testing Only**: Only scan systems you own or have explicit permission to assess. Checking the authorization box records operator intent and is not cryptographic proof of permission.
- **Scope Limitations**: Probes are unauthenticated `GET`/`HEAD` requests only; authenticated flows, `POST` forms, multi-page crawling, and destructive exploitation are intentionally excluded.
- **Local Targets Blocked**: `localhost`, loopback, and private network IPs are blocked by default SSRF controls.
- **No Guarantee of Security**: An absence of detected findings (`No issue observed`) does not prove an application is free of vulnerabilities.

---

## Team MASALA DOSA — RAVENX 2026 (PS-4)

**Institution**: GLA University, Mathura


