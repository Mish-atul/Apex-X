<div align="center">

# APEX-X

### Android Malware Forensics & Threat Attribution Platform

Automated static analysis, sandboxed dynamic analysis, threat-infrastructure mapping and court-ready reporting for suspicious Android applications.

[![FastAPI](https://img.shields.io/badge/FastAPI-backend-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)](https://nextjs.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](#docker-deployment)
[![Tests](https://img.shields.io/badge/tests-44%20passing-success)](#testing)

</div>

---

## Overview

APEX-X was developed as a research internship project supporting cybercrime investigation in Bengaluru. Investigators regularly encounter fraudulent Android apps — fake traffic-challan, government-scheme, wedding-invitation and banking apps distributed over WhatsApp and SMS. APEX-X turns a suspicious APK into an evidence-grade case file in minutes:

1. **Upload** an APK (or a split-APK bundle).
2. **Static analysis** decompiles the app and extracts permissions, code indicators, packers and behaviour rules.
3. **Dynamic analysis** runs the app inside an automatically started Android emulator and records what it actually does — network connections, sensitive-API use, background services and any secondary apps it installs.
4. **Intelligence** correlates indicators with threat-intelligence feeds and other cases.
5. **Reporting** produces a risk-scored case with multilingual PDF reports.

No physical phone or USB connection is required.

---

## Key Features

### Static analysis
| Capability | Tooling |
|---|---|
| Decompilation | APKTool (with resource-free fallback), JADX |
| Permissions, APIs, certificate | Androguard |
| Manifest and component exposure | Custom parser (exported components, debuggable, backup, cleartext) |
| Malware signatures | YARA |
| Behaviour rules | Quark-Engine (280 rules) |
| Packer / obfuscator / anti-analysis detection | APKiD |
| Indicators of compromise | URL, domain, IP, email and secret extraction with source references |
| Backend-as-a-Service exposure, remote-access tooling, fingerprinting | Custom detectors |

### Dynamic analysis (emulator sandbox)
- Boots an Android emulator automatically and installs the sample (including split-APK bundles and apps targeting old SDK levels).
- Handles malformed APKs that standard tools reject, so samples still install and run.
- Exercises the app with a UI-aware explorer (reads each screen, taps through onboarding, fills forms with placeholder data) followed by randomised UI events.
- Delivers realistic device events — an incoming SMS, a location fix, low battery and system broadcasts — so trigger-based behaviour shows up during the run.
- Records evidence attributed to the app's own Android user ID: its logs, open network connections, a packet capture of emulator traffic (DNS names, server names, byte counts), runtime permission use and running services.
- **Child-app tracking:** detects any app the sample installs during the run, then tracks that app's network activity, logs and permissions and pulls its APK for hashing.
- Optional Frida instrumentation records sensitive API calls.
- Manual analyst mode on the emulator or a connected phone.
- Falls back to a clearly labelled code-level scan if no emulator is available.

### Intelligence and scoring
- Threat-infrastructure graph with IP and domain enrichment (cloud/private ranges, suspicious TLDs, algorithmically generated domains).
- VirusTotal enrichment: detection ratio, malware-family attribution, sandbox verdicts.
- Cross-case correlation on shared domains, IPs, backend projects and identical samples.
- OWASP Mobile Top 10 mapping with CWE and CVSS.
- Evidence-based threat score: confirmed malware families and observed dropper behaviour raise the floor, so real malware is not under-scored.

### Reporting and interface
- PDF reports in English, Hindi, Kannada, Tamil and Telugu.
- Evidence package and IOC export (CSV, JSON, STIX 2.1).
- Web dashboard with per-case Overview, Static, Dynamic, C2 and Vulnerability tabs, live analysis progress and a reports index.

---

## Architecture

```
            ┌──────────────── Next.js frontend (:3000) ────────────────┐
            │ Dashboard · Upload · Case tabs · Reports · Threat map    │
            └──────────────────────────┬───────────────────────────────┘
                                       │ REST (JWT)
            ┌──────────────────────────▼───────────────────────────────┐
            │                 FastAPI backend (:8080)                  │
            │  upload ─► static ─► dynamic ─► C2 intel ─► vuln ─► score │
            └───┬──────────────┬─────────────────┬──────────────────┬──┘
                │              │                 │                  │
       SQLite / Postgres   case files      Android emulator     VirusTotal,
       (cases, results)   (data/cases)   via adb + Frida     IPinfo, Sarvam
```

| Path | Purpose |
|---|---|
| `backend/app/api/routes` | REST endpoints (auth, upload, cases, reports, copilot) |
| `backend/app/engines/static` | Decompilation, Androguard, YARA, APKiD, Quark, IOC extraction |
| `backend/app/engines/dynamic` | Emulator lifecycle, UI explorer, capture, Frida, manual analyst mode |
| `backend/app/engines/c2` | Threat graph, infrastructure enrichment, cross-case correlation |
| `backend/app/engines/vulnerability` | OWASP scan, CWE/CVSS mapping, narratives |
| `backend/app/services` | Background orchestration and threat scoring |
| `frontend/src/app` | Next.js pages (dashboard, cases, upload, reports) |
| `tools/` | APKTool and JADX binaries (Frida server downloaded on demand) |
| `docs/` | Dynamic-analysis guide, submission summary, project documents |
---

## Getting Started (local)

### Prerequisites
- Python 3.12, Node.js 20+, Java 17 (for APKTool/JADX)
- Android SDK with `platform-tools`, `emulator` and a `google_apis` x86_64 system image
- Hardware virtualization enabled (WHPX on Windows, KVM on Linux)

### 1. Create the analysis emulator (one time)
```bash
sdkmanager "system-images;android-35;google_apis;x86_64"
avdmanager create avd -n ApexX_Sandbox -k "system-images;android-35;google_apis;x86_64" -d medium_phone
```
The backend boots this AVD automatically when an analysis needs it.

### 2. Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate            # Windows  (source venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
freshquark                       # downloads Quark-Engine rules
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### 3. Frontend
```bash
cd frontend
npm install
echo NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1 > .env.local
npm run dev
```

Open http://localhost:3000. On Windows, `start_apex.bat` starts both services.

---

## Docker Deployment

See [docs/DOCKER.md](docs/DOCKER.md) for the full guide. In short:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Android emulators cannot run inside Docker on Windows, so the containerised backend reaches the emulator through the host's adb server (`ADB_SERVER_SOCKET=tcp:host.docker.internal:5037`). Start the emulator on the host (`launch_emulator.bat`) before running dynamic analysis. Static analysis, intelligence, scoring and reporting run entirely inside the containers.

---

## Configuration

Settings are read from a `.env` file in the repository root (never commit it).

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | JWT signing key — **set a strong value in production** |
| `DATABASE_URL` | Database URL (defaults to SQLite in `backend/`) |
| `VIRUSTOTAL_API_KEY` | Threat-intelligence enrichment and malware-family attribution |
| `IPINFO_API_TOKEN` | IP geolocation / ASN enrichment |
| `SARVAM_API_KEY` | Report translation (Hindi, Kannada, Tamil, Telugu) |
| `APEX_CORS_ORIGINS` | Comma-separated allowed frontend origins |
| `APEX_DATA_DIR` | Root for case files, reports and indexes |
| `APEX_AUTO_DYNAMIC` | Run dynamic analysis automatically after upload (`1`) |
| `APEX_DYNAMIC_DURATION` | Seconds to exercise each app (default `90`) |
| `APEX_AVD_NAME` | Force a specific emulator AVD |
| `APEX_EMULATOR_HEADLESS` | Run the emulator without a window (`1`) |
| `APEX_ENABLE_FRIDA` | Enable Frida API monitoring (`1`) |

More dynamic-analysis options are documented in [docs/DYNAMIC_ANALYSIS.md](docs/DYNAMIC_ANALYSIS.md).

---

## API Overview

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/signup`, `/api/v1/auth/login` | Account creation and JWT login |
| `POST` | `/api/v1/cases/upload/` | Upload an APK or split-APK bundle |
| `GET` | `/api/v1/cases/` | List cases with threat scores |
| `GET` | `/api/v1/cases/{id}/results` | All phase results for a case |
| `POST` | `/api/v1/cases/{id}/dynamic/run` | Re-run dynamic analysis |
| `GET` | `/api/v1/cases/{id}/dynamic/status` | Live dynamic-analysis stage |
| `GET` | `/api/v1/cases/dynamic/emulator` | Emulator status |
| `GET` | `/api/v1/reports/{id}/download?language=` | PDF report |
| `GET` | `/api/v1/reports/{id}/evidence-package` | Evidence package (ZIP) |

Interactive documentation: http://localhost:8080/docs

---

## Testing

```bash
cd backend
venv\Scripts\python -m pytest tests -q
```
44 unit tests cover the dynamic parsers, child-app attribution, C2 enrichment and correlation, vulnerability scoring, split-APK bundles and APK repair. The frontend is type-checked with `npx tsc --noEmit` and builds with `npm run build`.

---

## Limitations

- Apps that detect emulators may suppress behaviour during dynamic analysis; APKiD flags such apps so analysts know results may be incomplete.
- Automated exploration cannot complete real logins or OTP flows.
- Network evidence covers endpoints, DNS names and traffic volume; message content of encrypted traffic is not captured.
- Malware-family names depend on VirusTotal knowing the sample.
- AI narratives and the Co-Pilot chat need a local Ollama model; without it, template narratives are used.

---

## Responsible Use

APEX-X is intended for authorised forensic analysis of suspicious applications by investigators and security researchers. Analyse samples only in the isolated emulator sandbox, handle case data according to applicable evidence and privacy rules, and keep API keys out of version control. Bundled test apps (DIVA, InsecureShop, AndroGoat) are open-source, intentionally vulnerable training applications.

---

## Acknowledgements

Built on open-source tools including APKTool, JADX, Androguard, YARA, APKiD, Quark-Engine, Frida, Scapy, FastAPI and Next.js.

<div align="center">

Developed by Atul Mishra as a research internship project in support of cybercrime investigation, Bengaluru.

</div>
