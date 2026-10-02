# APEX-X: Team Work Division & Task Allocation

**Project:** Agentic APK Profiling, Exploitation Intelligence & Threat Attribution Platform
**Team Size:** 4 Members | **Institution:** R V College of Engineering, Bengaluru
**Hackathon:** CIDE Hackathon 2026 | CID, Government of Karnataka

---

> [!CAUTION]
> **MANDATORY: Local-Only LLM Policy**
> All LLM inference (Llama 3 / any model) **MUST run locally on-premise**. **Zero external API calls** are permitted — no OpenAI, no Gemini, no Claude, no Anthropic, no cloud-based LLM endpoints. The APK files being analyzed are **real malicious samples** from active cybercrime investigations. Sending any fragment of these files, their decompiled code, extracted strings, IOCs, or investigation metadata to an external API would constitute a **critical security breach** and potential evidence chain contamination. Use tools like **Ollama, llama.cpp, vLLM, or HuggingFace Transformers** for fully air-gapped, local inference.

---

## Work Division Philosophy

The project is split into **4 independent workstreams** — each team member owns a full vertical slice of the platform that can be **developed, unit-tested, and demo'd in isolation** before final integration. Each member exposes a **well-defined interface** (JSON schemas, REST API contracts, function signatures) so that integration is plug-and-play.

```
┌──────────────────────────────────────────────────────────────────────┐
│                        INDEPENDENT DEVELOPMENT                       │
│                                                                      │
│  TM1: Backend +      TM2: Analysis     TM3: AI/LLM +    TM4: Frontend│
│  Infrastructure      Engines           Intelligence     + Reporting   │
│  ──────────────      ──────────        ─────────────    ────────────  │
│  FastAPI, DBs,       Static Engine,    Local LLM,       React UI,     │
│  Auth, Upload,       Docker, RBAC        Vuln Scanner      Attribution,     PDFs,         │
│                                        Co-Pilot         Evidence Pkg  │
│                                                                      │
│  Each member tests independently with mock data / stub interfaces    │
└──────────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────────┐
│                       INTEGRATION PHASE                              │
│  Connect all 4 workstreams → End-to-end pipeline testing →           │
│  Demo preparation → Final polish                                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Interface Contracts (Agreed Before Development)

Before any coding begins, all 4 members must agree on these shared contracts:

### API Contract (TM1 exposes, all consume)
```
POST   /api/v1/apk/upload          → { case_id, apk_hash, status }
GET    /api/v1/cases/{case_id}     → { case details + phase statuses }
POST   /api/v1/analysis/static     → triggers static analysis
POST   /api/v1/analysis/dynamic    → triggers dynamic analysis
POST   /api/v1/analysis/intel      → triggers intelligence pipeline
GET    /api/v1/results/{case_id}/{phase} → { phase results JSON }
POST   /api/v1/report/generate     → triggers report generation
GET    /api/v1/report/{case_id}    → { report download links }
WS     /api/v1/copilot/{case_id}   → WebSocket for Co-Pilot chat
```

### Data Exchange Format (All members use)
```json
{
  "case_id": "uuid",
  "apk_hash": "sha256",
  "phase": "static | dynamic | c2 | vuln | reasoning | reporting",
  "status": "pending | running | completed | failed",
  "result": { /* phase-specific JSON */ },
  "risk_score": 0-100,
  "timestamp": "ISO8601"
}
```

### Shared Git Branching Strategy
```
main
├── dev/tm1-backend-infra
├── dev/tm2-analysis-engines
├── dev/tm3-ai-intelligence
├── dev/tm4-frontend-reporting
└── integration (merge target before main)
```

---
---

# 👤 TEAM MEMBER 1 — Backend Infrastructure & Platform Core

**Role:** Backend Architect & DevOps
**Owns:** FastAPI backend, databases, authentication, Docker, APK upload pipeline, task queue

---

## Responsibilities

### 1.1 FastAPI Backend Core
- Initialize the FastAPI project with proper structure:
  ```
  apex_x/
  ├── main.py                    # App entry point
  ├── config.py                  # Environment configuration
  ├── api/
  │   ├── routes/
  │   │   ├── upload.py          # APK upload endpoints
  │   │   ├── cases.py           # Case management CRUD
  │   │   ├── analysis.py        # Analysis trigger endpoints
  │   │   ├── results.py         # Results retrieval
  │   │   ├── reports.py         # Report download endpoints
  │   │   └── auth.py            # Authentication routes
  │   ├── middleware/
  │   │   ├── rbac.py            # Role-based access control
  │   │   └── audit.py           # Audit logging middleware
  │   └── dependencies.py        # Shared dependencies
  ├── models/
  │   ├── database.py            # SQLAlchemy models
  │   ├── schemas.py             # Pydantic request/response schemas
  │   └── enums.py               # Status enums, role enums
  ├── services/
  │   ├── case_service.py        # Case business logic
  │   ├── hash_service.py        # SHA256 hashing utilities
  │   └── task_service.py        # Redis task queue management
  └── utils/
      ├── security.py            # JWT, password hashing
      └── file_utils.py          # APK file handling
  ```

### 1.2 Database Setup & Schema
- **PostgreSQL** — Set up with the full schema:
  - `users` table (id, username, role, hashed_password, created_at)
  - `cases` table (id, case_number, apk_hash, apk_name, status, created_by, timestamps)
  - `phase_results` table (id, case_id, phase, result JSONB, risk_score, completed_at)
  - `audit_logs` table (id, case_id, user_id, action, details JSONB, timestamp, ip_address)
  - `evidence_records` table (id, case_id, artifact_type, file_hash, file_path, collected_at)
- **Neo4j** — Initialize instance with graph schema (node types + relationship types as defined in project plan Section 9.2). TM1 sets up the instance; TM3 populates it.
- **ChromaDB** — Initialize instance with 4 collections:
  - `malware_behavior_embeddings`
  - `investigation_report_embeddings`
  - `threat_narrative_embeddings`
  - `ioc_pattern_embeddings`
- **Redis** — Set up for background task queue (Celery or ARQ)

### 1.3 APK Upload & Intake Pipeline
- REST endpoint for APK file upload (multipart form upload)
- File validation: check ZIP integrity, verify DEX file presence, validate manifest
- SHA256 hash computation on upload and storage in PostgreSQL
- Case creation with auto-generated case number
- Store original APK in encrypted local storage
- Return case_id to frontend for status tracking

### 1.4 Authentication & RBAC
- JWT-based authentication (login, token refresh, logout)
- 4 roles: Investigator, Analyst, Supervisor, Administrator
- Route-level permission middleware
- All actions logged to `audit_logs` table with user_id, action, timestamp, IP

### 1.5 Task Queue & Orchestration
- Background task management via Redis + Celery/ARQ
- Phase execution ordering: static → dynamic → c2 → vuln → reasoning → reporting
- Task status tracking (pending, running, completed, failed)
- Retry logic for failed phases
- WebSocket endpoint for real-time status updates to frontend

### 1.6 Docker Compose Environment
- Write `docker-compose.yml` with all services:
  ```yaml
  services:
    backend:     # FastAPI app
    postgres:    # PostgreSQL 16
    neo4j:       # Neo4j Community Edition
    chromadb:    # ChromaDB
    redis:       # Redis for task queue
    # TM2 adds: android-vm, frida
    # TM3 adds: ollama (local LLM)
    # TM4 adds: frontend (React + nginx)
  ```
- Shared Docker network for inter-service communication
- Volume mounts for persistent data and APK storage
- Environment variable management (.env file)

### 1.7 Cryptographic Integrity Infrastructure
- SHA256 hash utility used by ALL phases to hash every output artifact
- `sha256_manifest.json` builder — collects hashes from every phase
- HMAC-SHA256 package signing utility (used by TM4 for evidence packaging)
- Chain-of-custody JSON builder — timestamped action log

---

## Individual Testing Plan (TM1)

| Test | What to Verify | How |
|---|---|---|
| APK Upload | File accepted, hash computed, case created | Upload a test APK via curl/Postman, check DB |
| DB Schema | All tables created, relationships work | Run migrations, insert test data, verify FK constraints |
| RBAC | Role-based access enforced | Create users with different roles, test route access |
| Audit Logging | Every action logged | Perform actions, query audit_logs table |
| Task Queue | Tasks enqueue and execute | Submit a dummy task, verify Redis + worker processes it |
| Docker | All containers start and communicate | `docker-compose up`, verify each service health endpoint |
| Hash Integrity | SHA256 computed correctly | Hash known files, compare with `sha256sum` CLI output |
| WebSocket | Status updates stream to client | Connect via wscat, trigger a task, see status messages |

---
