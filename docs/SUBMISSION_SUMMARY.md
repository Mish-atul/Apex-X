# APEX-X — Submission Summary

A full-stack Android malware analysis platform. Upload an APK and it runs static
analysis, **real dynamic analysis inside an auto-booted Android emulator**, C2
intelligence, and a vulnerability scan, then presents everything in a web UI
with downloadable multilingual forensic reports.

## What works end to end

- **Static analysis** — APKTool + JADX decompilation, Androguard (permissions,
  APIs, certificate), manifest parsing, YARA rules, IOC extraction, BaaS and
  remote-access detection, fingerprinting. Real output from the engines.
- **Dynamic analysis** — the backend boots an Android emulator automatically
  (no phone, no USB), installs the app, instruments it with **Frida** (sensitive
  API monitor + optional TLS interception), drives the UI with Monkey, injects
  external stimuli (SMS/OTP, GPS, battery, connectivity, broadcasts), and
  collects UID-scoped evidence: logcat, sockets, a full packet capture (DNS/SNI),
  AppOps usage, running services, per-UID traffic and dropped-APK detection.
  See `DYNAMIC_ANALYSIS.md`.
- **C2 intelligence** — threat-infrastructure graph with IP/domain enrichment
  (private/cloud classification, suspicious TLDs, DGA detection) and cross-case
  correlation.
- **Vulnerability scan** — OWASP Mobile Top 10 mapping, CWE + CVSS, and
  AI-generated PoC narratives (local LLM, with template fallback).
- **Reports** — per-case English/Hindi/Kannada/Tamil/Telugu PDFs and a
  Section 65B evidence package, plus IOC export (CSV/JSON/STIX).

## No synthetic data

The web UI now renders **only real backend data**. The previous build injected
three hardcoded demo cases into every list, returned mock case details, and fell
back to large synthetic datasets in the tabs, dashboard and documents page. All
of that was removed: `services/realData.ts` is now types-only, `getCases`/
`getCaseDetail` return live API data only, and every tab reads real analysis
results. Accuracy and honest limitations are documented in `DYNAMIC_ANALYSIS.md`.

## Quality

- Backend: 39 unit tests passing. Previously-broken modules rebuilt
  (`correlation_engine`, `infra_enricher`) and their tests restored.
- Frontend: TypeScript clean, production build passes (Next.js 16 / React 19).
- Professional UI: toast notifications and confirm dialogs replace raw
  `alert()`/`confirm()`, skeleton loading states, framer-motion transitions.
- Hardening: centralised data paths and DB location, configurable CORS
  allow-list (no `*`-with-credentials), SECRET_KEY warning, Pydantic v2 config.

## Running it

1. `start_apex.bat` launches the backend (`:8080`) and frontend (`:3000`).
2. Open http://localhost:3000, sign in, and upload an APK. Analysis — including
   the emulator run — proceeds automatically; the case page shows live progress
   and reloads with results.

Prerequisites and tuning for the emulator/Frida layer are in `DYNAMIC_ANALYSIS.md`.

## Pre-analysed demo cases

The database ships with completed cases for showcasing, including real malware
samples (fake RTO/e-challan/government-scheme APKs) scoring 98–100, and the
bundled vulnerable test apps (AndroGoat, InsecureShop, DivaApplication) with
real static + emulator-dynamic results.
