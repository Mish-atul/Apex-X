# APEX-X: Project Plan
## Agentic APK Profiling, Exploitation Intelligence & Threat Attribution Platform

**CIDE Hackathon 2026 | Criminal Investigation Department (CID), Government of Karnataka**
**Team Institution:** R V College of Engineering, Bengaluru | **Date:** June 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Hackathon Requirements Checklist](#2-hackathon-requirements-checklist)
3. [Architecture & Technical Design Plan](#3-architecture--technical-design-plan)
4. [Six-Phase Implementation Pipeline](#4-six-phase-implementation-pipeline)
5. [12-Week Development Roadmap](#5-12-week-development-roadmap)
6. [Sprint-Level Task Breakdown](#6-sprint-level-task-breakdown)
7. [Agent Design Plan](#7-agent-design-plan)
8. [Module Implementation Plan](#8-module-implementation-plan)
9. [Data Layer Design Plan](#9-data-layer-design-plan)
10. [Frontend & Presentation Plan](#10-frontend--presentation-plan)
11. [Security & Compliance Plan](#11-security--compliance-plan)
12. [Testing & Validation Plan](#12-testing--validation-plan)
13. [Team Roles & Responsibilities](#13-team-roles--responsibilities)
14. [Risk Register](#14-risk-register)
15. [Deliverables Checklist](#15-deliverables-checklist)
16. [Success Metrics & KPIs](#16-success-metrics--kpis)

---

## 1. Project Overview

### What We Are Building

APEX-X is a **full-spectrum APK investigation and threat analysis platform** — not a scanner or parser. It automates the entire malware investigation lifecycle: from uploading a suspicious APK to generating a court-ready Section 65B evidence package with multilingual forensic reports.

### The Problem It Solves

| Problem | Impact |
|---|---|
| Manual APK investigation takes days | Delays in criminal proceedings |
| Technical outputs inaccessible to officers | Intelligence is lost in translation |
| No cross-case correlation | Repeat threat actors go undetected |
| No court-admissible evidence generation | Investigations fail in court |
| No multilingual reporting | State-level law enforcement excluded |

### Platform Tagline

> *Build an APK investigation and threat analysis platform — not just a parser or scanner.*

### Core Four-Step Mission

```
DETECT → IDENTIFY → CORRELATE → REPORT
```

---

## 2. Hackathon Requirements Checklist

This section maps every requirement from the hackathon brief (as seen in the presentation images) to corresponding APEX-X implementation features.

### ✅ Feature Area 1: Technical Capability

| Requirement | Implementation | Status |
|---|---|---|
| APK Analysis & Metadata Extraction | APKTool + Androguard + JADX decompilation pipeline | Planned |
| Permission & Manifest Analysis | Manifest parser with dangerous-permission classification | Planned |
| Runtime Monitoring | Frida instrumentation + API hook recording | Planned |
| Network Traffic & Endpoint Analysis | mitmproxy + tcpdump + DNS logger | Planned |
| Obfuscation & Suspicious Pattern Detection | YARA rules + ProGuard detection + dynamic loading detector | Planned |

### ✅ Feature Area 2: Behavioral Correlation

| Requirement | Implementation | Status |
|---|---|---|
| Correlate Permissions ↔ Runtime Behavior | Behavioral diff engine: declared vs observed | Planned |
| Correlate Static Findings ↔ Network Activity | Cross-reference IOCs with PCAP analysis | Planned |
| Detect Persistence & Hidden Actions | Background service tracker + persistence mechanism detector | Planned |
| Detect Data Exfiltration / C2-Controlled Behavior | C2 command handler detector in Smali + network pattern analysis | Planned |

### ✅ Feature Area 3: Investigation Relevance

| Requirement | Implementation | Status |
|---|---|---|
| What does it actually do? | AI behavioral summary via Llama 3 LLM | Planned |
| What data does it access? | Data access profiler (contacts, SMS, location, camera) | Planned |
| Who does it communicate with? | C2 Intelligence Graph (Neo4j) | Planned |
| Is there evidence of malicious behavior? | Threat verdict with evidence chain | Planned |

### ✅ Feature Area 4: Reporting & Visualization

| Requirement | Implementation | Status |
|---|---|---|
| Investigator Dashboard | React + Tailwind CSS real-time dashboard | Planned |
| Behavior Timeline | D3.js interactive event timeline | Planned |
| Network Flow Visualization | PyVis + D3.js interactive network graph | Planned |
| Structured Forensic Reports | ReportLab PDF generator with audit trails | Planned |
| Risk Summaries & IOCs | IOC extraction module + risk scoring engine | Planned |

### ✅ Core Platform Requirements

| Requirement | Implementation | Status |
|---|---|---|
| Static & Dynamic Analysis | Hybrid analysis pipeline (Phases 1 & 2) | Planned |
| Suspicious Behavior & C2 Detection | C2 Intelligence Engine + behavioral correlation | Planned |
| Correlation Engine | Neo4j graph + historical similarity search | Planned |
| Forensic Artifact Extraction | SHA256 hashing + artifact collection at every phase | Planned |
| Dashboards & Reports | Full Presentation Layer (Tier 4) | Planned |

### ✅ Bonus Points (Innovation Encouraged)

| Innovation | Implementation | Status |
|---|---|---|
| AI-Assisted Behavioral Summaries | Llama 3 + ChromaDB RAG pipeline | Planned |
| Threat Scoring | Composite CVSS + behavioral score engine | Planned |
| IOC Extraction | Automated IOC extractor for all artifact types | Planned |
| Advanced Visualizations | D3.js + PyVis interactive intelligence graphs | Planned |
| Threat Intelligence Integration | Internal historical intelligence graph enrichment | Planned |

---

## 3. Architecture & Technical Design Plan

### 3.1 Four-Tier Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                 TIER 1: AGENTIC ORCHESTRATION                     │
│   Intake → Static → Dynamic → Vulnerability → Attribution →       │
│   Reasoning (LLM) → Reporting → [Supervisor Agent manages all]    │
└───────────────────────────┬───────────────────────────────────────┘
                            ↕
┌───────────────────────────────────────────────────────────────────┐
│                   TIER 2: INTELLIGENCE LAYER                      │
│  Static Engine | Dynamic Engine | Vulnerability Engine |          │
│  C2 Intelligence | AI PoC | Attribution | Historical Correlation  │
└───────────────────────────┬───────────────────────────────────────┘
                            ↕
┌───────────────────────────────────────────────────────────────────┐
│                       TIER 3: DATA LAYER                          │
│  Neo4j (Graph)  |  PostgreSQL (Relational)  |  ChromaDB (Vector)  │
└───────────────────────────┬───────────────────────────────────────┘
                            ↕
┌───────────────────────────────────────────────────────────────────┐
│                   TIER 4: PRESENTATION LAYER                      │
│  Dashboard | Graph Viz | Co-Pilot | Multilingual | Evidence Pkg   │
└───────────────────────────────────────────────────────────────────┘
                            ↕
┌───────────────────────────────────────────────────────────────────┐
│              INFRASTRUCTURE & SECURITY (Cross-Cutting)            │
│  Air-Gapped | RBAC | SHA256 | Chain-of-Custody | Backup          │
└───────────────────────────────────────────────────────────────────┘
```

### 3.2 Technology Selection Rationale

| Technology | Selected Tool | Reason |
|---|---|---|
| APK Decompilation | APKTool + JADX + Androguard | Best-in-class open-source trio; JADX for Java output, Androguard for API analysis |
| Dynamic Hooking | Frida | Industry standard for Android runtime instrumentation |
| Traffic Interception | mitmproxy | Python-native, scriptable, supports SSL stripping |
| Graph Database | Neo4j | Native support for complex relationship queries; industry standard for threat intelligence |
| Vector Search | ChromaDB | Lightweight, open-source, integrates natively with LangChain |
| LLM Runtime | Llama 3 (local) | State-of-the-art open-source model; air-gapped compatible |
| Agent Framework | LangChain + LangGraph | Production-grade agentic workflow orchestration |
| Backend API | FastAPI | Async Python, high performance, auto-documented OpenAPI |
| Frontend | React + Tailwind CSS | Component-based, rapid development, responsive |
| Forensic Reporting | ReportLab | Pure Python, court-document quality PDF generation |

### 3.3 Data Flow Design

```
APK File
   ↓
[Intake Agent] → SHA256 hash, validate APK signature
   ↓
[Static Analysis Agent]
   ├── APKTool → Decompile → Smali + Resources
   ├── JADX → Java source reconstruction
   ├── Androguard → Permissions, API calls, CFG
   └── YARA → Pattern matching
   ↓
[Dynamic Analysis Agent]
   ├── Android-x86 VM → Execute APK
   ├── Frida → Hook APIs, system calls
   ├── mitmproxy → Decrypt HTTPS traffic
   └── tcpdump → Capture raw PCAP
   ↓
[Intelligence Layer]
   ├── C2 Engine → Build infrastructure graph in Neo4j
   ├── Vulnerability Engine → OWASP scan, CVSS scoring
   ├── Attribution Engine → GNN-based family classification
   └── Historical Engine → Vector similarity search (ChromaDB)
   ↓
[Reasoning Agent] → LLM generates threat narrative
   ↓
[Reporting Agent] → Multilingual PDF + Section 65B package
```

---

## 4. Six-Phase Implementation Pipeline

### Phase 1: Static APK Analysis

**Objective:** Analyze the APK without executing it to extract all visible indicators and establish a risk baseline.

**Steps:**
1. Receive APK via REST API upload endpoint
2. Compute SHA256 hash and store in PostgreSQL with case metadata
3. Validate APK structure (ZIP integrity, DEX files, manifest presence)
4. Decompile using APKTool (Smali output) and JADX (Java output)
5. Parse `AndroidManifest.xml`:
   - Extract all `<uses-permission>` declarations
   - Map to dangerous/normal/signature classification
   - Identify exported components (activities, services, receivers, providers)
6. Run Androguard analysis:
   - Generate Control Flow Graph (CFG)
   - Extract all API calls and classify by risk category
   - Identify hardcoded strings, URLs, IPs, domains
7. Run YARA rules against all extracted files
8. Compute static risk score (0-100) based on permission profile, API usage, YARA hits

**Output Artifacts:**
- `static_report.json` — full findings
- `permissions_profile.json` — permission classification
- `ioc_list.json` — initial IOC set
- `static_risk_score` — numerical risk assessment

### Phase 2: Dynamic Sandbox Analysis

**Objective:** Execute the APK in a controlled environment to observe actual runtime behavior.

**Steps:**
1. Spin up isolated Android-x86 VM instance
2. Install and launch APK via ADB
3. Attach Frida agent for runtime instrumentation:
   - Hook sensitive API classes (camera, microphone, SMS, contacts, location)
   - Record all method calls with arguments and return values
4. Run Monkey automation tool for UI interaction (stress testing)
5. Start mitmproxy with certificate pinning bypass
6. Capture PCAP via tcpdump
7. Monitor file system changes (inotify)
8. Monitor process tree (ps, procfs)
9. Record all DNS queries
10. Run for configurable duration (default: 5 minutes)
11. Extract behavioral profile: API sequence, network contacts, file operations

**Output Artifacts:**
- `runtime_behavior.json` — full behavioral trace
- `network_traffic.pcap` — raw packet capture
- `decrypted_http.json` — mitmproxy decoded traffic
- `api_trace.json` — Frida hook recordings
- `behavioral_risk_score` — runtime risk assessment

### Phase 3: C2 Intelligence & Malware Attribution

**Objective:** Build a threat intelligence graph and attribute the malware to known families/campaigns.

**Steps:**
1. Collect all network indicators from Phases 1 & 2:
   - Domains, IP addresses, URLs, SSL certificate fingerprints
2. Construct Neo4j graph nodes and relationships
3. Enrich with historical investigation data (existing Neo4j nodes)
4. Run Graph Neural Network model for:
   - Infrastructure cluster detection
   - Malware family similarity scoring
   - Campaign relationship identification
5. Cross-reference against ChromaDB embeddings for similar past cases
6. Generate attribution confidence score
7. Identify potential threat actor profiles

**Output Artifacts:**
- `c2_graph.json` — Neo4j graph export
- `attribution_report.json` — malware family + confidence score
- `campaign_links.json` — related historical cases
- Infrastructure visualization data for frontend

### Phase 4: Vulnerability Discovery & AI PoC Generation

**Objective:** Identify security weaknesses and explain their exploitability in plain language.

**Steps:**
1. OWASP Mobile Top 10 Assessment:
   - M1: Improper Credential Usage (hardcoded keys, credentials)
   - M2: Inadequate Supply Chain Security
   - M3: Insecure Authentication/Authorization
   - M4: Insufficient Input/Output Validation
   - M5: Insecure Communication (SSL bypass, custom trust managers)
   - M6: Inadequate Privacy Controls
   - M7: Insufficient Binary Protections (no obfuscation, debuggable)
   - M8: Security Misconfiguration (exported components, backup enabled)
   - M9: Insecure Data Storage (SQLite plain text, SharedPreferences)
   - M10: Insufficient Cryptography (weak algorithms, hardcoded keys)
2. CWE mapping for each finding
3. CVSS v3.1 scoring for each vulnerability
4. AI PoC narrative generation via Llama 3:
   - Explain what the vulnerability enables
   - Describe the attack scenario in plain language
   - Recommend remediation (for court context: demonstrate exploitability)

**Output Artifacts:**
- `vulnerability_report.json` — all findings with CVSS scores
- `owasp_assessment.json` — OWASP category results
- `poc_narratives.json` — AI-generated exploitability explanations

### Phase 5: Agentic Investigation & Threat Reasoning

**Objective:** Synthesize all findings into coherent investigative intelligence using AI agents.

**Steps:**
1. Supervisor Agent aggregates all phase outputs
2. Threat Reasoning Agent (LLM) performs:
   - Evidence correlation across all phases
   - Smali code explanation in natural language
   - Behavioral intent assessment (data theft, surveillance, financial fraud, etc.)
   - Threat narrative construction (who, what, how, impact)
3. Investigation lead generation
4. Recommended next investigative actions
5. Evidence chain construction (what evidence supports what conclusion)
6. Officer Co-Pilot preparation (pre-load investigation context into RAG)

**Output Artifacts:**
- `threat_narrative.json` — full investigative narrative
- `evidence_chain.json` — findings-to-conclusions mapping
- `investigative_leads.json` — recommended next steps
- `copilot_context.json` — RAG context for Q&A

### Phase 6: Multilingual Reporting & Evidence Packaging

**Objective:** Produce court-ready, multilingual, cryptographically verified investigation reports.

**Steps:**
1. Compile master investigation report from all phase outputs
2. Generate translations via Indic NLP pipeline:
   - English (primary)
   - Kannada (KN)
   - Hindi (HI)
   - Tamil (TA)
   - Telugu (TE)
3. Generate Section 65B evidence certificate:
   - Case metadata + analyst information
   - File hashes for all evidence items
   - System-generated timestamp certification
   - Chain-of-custody log
4. Package all artifacts into cryptographically signed ZIP
5. Generate executive summary (2-page version for senior officers)

**Output Artifacts:**
- `investigation_report_EN.pdf`
- `investigation_report_KN.pdf`
- `investigation_report_HI.pdf`
- `investigation_report_TA.pdf`
- `investigation_report_TE.pdf`
- `section_65b_evidence_package.zip` (signed)
- `executive_summary.pdf`
- `audit_log.json`

---

## 5. 12-Week Development Roadmap

| Phase | Weeks | Focus | Key Deliverables |
|---|---|---|---|
| **Phase 1: Core Infrastructure** | 1–2 | Foundation setup | FastAPI backend, PostgreSQL schema, APK upload API, Docker Compose environment |
| **Phase 2: Malware Analysis Engine** | 3–4 | Analysis pipeline | Static analysis (APKTool, JADX, Androguard, YARA), dynamic sandbox (Frida, mitmproxy, Android VM), IOC extraction |
| **Phase 3: Intelligence Layer** | 5–6 | Graph & attribution | Neo4j C2 graph construction, GNN attribution model, ChromaDB vector search, historical correlation |
| **Phase 4: AI Investigation Layer** | 7–8 | LLM integration | Llama 3 local deployment, LangChain agent pipeline, LangGraph supervisor, Officer Co-Pilot interface |
| **Phase 5: Advanced Features** | 9–10 | Innovation features | Vulnerability discovery engine, AI PoC generation, multilingual reporting pipeline, advanced visualizations |
| **Phase 6: Testing & Deployment** | 11–12 | QA & finalization | Integration testing, Section 65B packaging, air-gap deployment validation, demo preparation |

---

## 6. Sprint-Level Task Breakdown

### Weeks 1–2: Core Infrastructure

**Backend Setup:**
- [ ] Initialize FastAPI project structure
- [ ] Configure PostgreSQL with investigation schema
- [ ] Set up Redis for task queuing
- [ ] Build APK upload endpoint with validation
- [ ] Implement SHA256 hashing and case creation
- [ ] Configure Docker Compose for all services
- [ ] Set up RBAC middleware (JWT-based)
- [ ] Initialize Neo4j instance with schema
- [ ] Set up ChromaDB instance

**Environment:**
- [ ] Configure Android-x86 VM base image
- [ ] Set up Frida server on VM
- [ ] Configure ADB connectivity
- [ ] Set up mitmproxy with certificate authority

### Weeks 3–4: Malware Analysis Engine

**Static Analysis:**
- [ ] Integrate APKTool decompilation module
- [ ] Integrate JADX Java source extraction
- [ ] Integrate Androguard API for permissions, CFG, strings
- [ ] Build YARA rule set for Android malware patterns
- [ ] Develop manifest parser for permissions and components
- [ ] Build IOC extractor (URLs, IPs, domains from strings)
- [ ] Implement static risk scoring algorithm

**Dynamic Analysis:**
- [ ] Build VM orchestration module (start/stop/snapshot)
- [ ] Develop Frida script set for Android API hooking
- [ ] Integrate Monkey automation for UI interaction
- [ ] Build mitmproxy decoder for HTTPS traffic
- [ ] Implement PCAP capture via tcpdump wrapper
- [ ] Build behavioral profile aggregator

### Weeks 5–6: Intelligence Layer

**C2 Intelligence:**
- [ ] Design Neo4j graph schema (nodes and relationships)
- [ ] Build C2 graph construction pipeline
- [ ] Implement domain/IP/URL enrichment logic
- [ ] Develop SSL certificate extraction and parsing

**Attribution:**
- [ ] Train/configure GNN model for malware family classification
- [ ] Build behavioral fingerprinting module
- [ ] Implement ChromaDB embedding indexer
- [ ] Develop historical case similarity search
- [ ] Build attribution confidence scoring

### Weeks 7–8: AI Investigation Layer

**LLM Infrastructure:**
- [ ] Deploy Llama 3 locally (GPU or CPU inference)
- [ ] Configure ChromaDB RAG pipeline with LangChain
- [ ] Build LangGraph supervisor agent workflow
- [ ] Develop Static Analysis Agent tool set
- [ ] Develop Dynamic Analysis Agent tool set
- [ ] Develop Attribution Agent tool set
- [ ] Develop Threat Reasoning Agent with Smali-to-English translator
- [ ] Build Officer Co-Pilot chat interface (REST + WebSocket)

### Weeks 9–10: Advanced Features

**Vulnerability Discovery:**
- [ ] Implement OWASP Mobile Top 10 automated scanner
- [ ] Build CWE mapping database
- [ ] Integrate CVSS v3.1 scoring calculator
- [ ] Develop AI PoC narrative generator (Llama 3 prompt chain)

**Multilingual Reporting:**
- [ ] Set up Indic NLP translation pipeline (KN, HI, TA, TE)
- [ ] Build ReportLab PDF generation templates
- [ ] Implement Section 65B certificate generator
- [ ] Build chain-of-custody documentation module

**Advanced Visualizations:**
- [ ] Develop D3.js network infrastructure graph component
- [ ] Build interactive behavior timeline (D3.js)
- [ ] Integrate PyVis for malware attribution graphs
- [ ] Build threat score visualization component

### Weeks 11–12: Testing & Deployment

**Testing:**
- [ ] Integration testing with known malware samples (BankBot, SpyNote, etc.)
- [ ] End-to-end pipeline validation
- [ ] Performance testing (APK analysis time targets)
- [ ] Security penetration testing of platform
- [ ] Section 65B package legal compliance review
- [ ] Multilingual report accuracy validation

**Deployment:**
- [ ] Air-gap deployment configuration
- [ ] Backup and disaster recovery setup
- [ ] Final dashboard UI polish
- [ ] Demo environment preparation
- [ ] Documentation finalization

---

## 7. Agent Design Plan

### 7.1 Supervisor Agent

**Framework:** LangGraph StateGraph
**Responsibilities:**
- Maintain global investigation state
- Route tasks to appropriate sub-agents
- Handle agent failures and retry logic
- Coordinate parallel execution where possible
- Aggregate final results for reporting

**State Schema:**
```json
{
  "case_id": "string",
  "apk_hash": "string",
  "current_phase": "enum[intake, static, dynamic, c2, vuln, reasoning, reporting]",
  "phase_results": "dict",
  "error_log": "list",
  "investigation_complete": "boolean"
}
```

### 7.2 Static Analysis Agent

**Tools Available:**
- `run_apktool(apk_path)` → returns decompiled directory
- `run_jadx(apk_path)` → returns Java source directory
- `analyze_with_androguard(apk_path)` → returns permission set, API list, CFG
- `run_yara_scan(directory)` → returns rule match results
- `extract_iocs(strings_file)` → returns URL/IP/domain list
- `parse_manifest(manifest_path)` → returns permission and component map

**Output:** Structured JSON with all static findings and risk score

### 7.3 Dynamic Analysis Agent

**Tools Available:**
- `start_sandbox_vm(vm_name)` → boots Android VM
- `install_apk(apk_path, vm_name)` → installs APK via ADB
- `attach_frida(pid, script)` → hooks runtime API
- `start_monkey(package, events)` → runs UI automation
- `capture_traffic(duration)` → starts mitmproxy + tcpdump
- `collect_artifacts()` → retrieves logs, PCAP, Frida output
- `stop_sandbox_vm(vm_name)` → terminates VM

**Output:** Runtime behavioral profile, network traffic analysis

### 7.4 Vulnerability Agent

**Tools Available:**
- `run_owasp_scanner(decompiled_dir)` → returns OWASP category findings
- `map_cwe(finding)` → returns CWE identifier
- `compute_cvss(finding)` → returns CVSS v3.1 score
- `generate_poc_narrative(vuln, llm)` → returns plain language PoC explanation

**Output:** Vulnerability report with CVSS scores and AI narratives

### 7.5 Attribution Agent

**Tools Available:**
- `query_neo4j_infrastructure(ioc_list)` → returns related nodes/campaigns
- `run_gnn_classification(behavioral_profile)` → returns malware family
- `search_chromadb_similarity(embedding)` → returns similar past cases
- `compute_attribution_confidence(matches)` → returns score

**Output:** Malware family classification, related campaigns, confidence score

### 7.6 Threat Reasoning Agent (LLM)

**Framework:** LangChain ReAct agent with ChromaDB RAG
**System Prompt:** Configured as expert malware investigator
**Capabilities:**
- Synthesize findings across all phases
- Translate Smali code to plain English
- Generate attacker intent hypothesis
- Write investigation narrative
- Answer Officer Co-Pilot queries

**Output:** Threat narrative, evidence chain, investigative leads

### 7.7 Reporting Agent

**Tools Available:**
- `compile_master_report(all_phase_outputs)` → structured report object
- `translate_report(report, language)` → translated content
- `generate_pdf(report, template, language)` → PDF file
- `generate_section_65b_package(report, hashes)` → evidence package
- `sign_package(package, key)` → cryptographically signed ZIP

**Output:** PDFs in 5 languages, Section 65B package, audit log

---

## 8. Module Implementation Plan

### 8.1 Static Analysis Engine

**File Structure:**
```
apex_x/
├── engines/
│   ├── static/
│   │   ├── apktool_wrapper.py
│   │   ├── jadx_wrapper.py
│   │   ├── androguard_analyzer.py
│   │   ├── manifest_parser.py
│   │   ├── yara_scanner.py
│   │   ├── ioc_extractor.py
│   │   └── risk_scorer.py
```

**Key Functions:**
- `decompile_apk(apk_path) → DecompileResult`
- `analyze_permissions(manifest) → PermissionProfile`
- `extract_indicators(decompile_result) → IOCList`
- `compute_static_risk(findings) → int (0-100)`

### 8.2 Dynamic Behavior Engine

```
apex_x/
├── engines/
│   ├── dynamic/
│   │   ├── vm_orchestrator.py
│   │   ├── frida_scripts/
│   │   │   ├── sms_hook.js
│   │   │   ├── network_hook.js
│   │   │   ├── crypto_hook.js
│   │   │   └── file_hook.js
│   │   ├── mitmproxy_decoder.py
│   │   ├── pcap_analyzer.py
│   │   └── behavior_aggregator.py
```

### 8.3 C2 Intelligence Engine

```
apex_x/
├── engines/
│   ├── c2/
│   │   ├── graph_builder.py       # Constructs Neo4j graph
│   │   ├── ssl_extractor.py       # Parses SSL certificates
│   │   ├── infra_enricher.py      # Enriches with WHOIS/GeoIP
│   │   └── cluster_detector.py    # GNN-based clustering
```

**Neo4j Cypher Queries (Key Examples):**
```cypher
// Create APK node
CREATE (a:APK {hash: $hash, package: $package, name: $name, case_id: $case_id})

// Link APK to domain
MATCH (a:APK {hash: $hash}), (d:Domain {name: $domain})
CREATE (a)-[:COMMUNICATES_WITH]->(d)

// Find related campaigns
MATCH (apk:APK)-[:COMMUNICATES_WITH]->(d:Domain)<-[:USES]-(c:Campaign)
WHERE apk.hash = $hash
RETURN c, d
```

### 8.4 Vulnerability Discovery Engine

```
apex_x/
├── engines/
│   ├── vulnerability/
│   │   ├── owasp_scanner.py      # OWASP Mobile Top 10 checks
│   │   ├── cwe_mapper.py         # CWE database lookup
│   │   ├── cvss_calculator.py    # CVSS v3.1 scoring
│   │   └── poc_generator.py      # LLM-based PoC narratives
```

**OWASP Check Categories:**
```python
OWASP_CHECKS = {
    "M1": check_improper_credential_usage,
    "M3": check_authentication_weaknesses,
    "M5": check_insecure_communication,
    "M7": check_binary_protections,
    "M8": check_security_misconfiguration,
    "M9": check_insecure_data_storage,
    "M10": check_weak_cryptography,
}
```

---

## 9. Data Layer Design Plan

### 9.1 PostgreSQL Schema

```sql
-- Cases table
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_number VARCHAR(50) UNIQUE NOT NULL,
    apk_hash VARCHAR(64) NOT NULL,
    apk_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMP
);

-- Investigation phases
CREATE TABLE phase_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id),
    phase VARCHAR(50) NOT NULL,
    result JSONB,
    risk_score INTEGER,
    completed_at TIMESTAMP
);

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address VARCHAR(45)
);

-- Evidence records
CREATE TABLE evidence_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id),
    artifact_type VARCHAR(50),
    file_hash VARCHAR(64) NOT NULL,
    file_path VARCHAR(500),
    collected_at TIMESTAMP DEFAULT NOW()
);
```

### 9.2 Neo4j Graph Schema

**Node Types:**
```
(:APK {hash, package_name, name, first_seen, threat_score})
(:Domain {name, first_seen, registrar, country})
(:IPAddress {address, asn, country, hosting_provider})
(:URL {full_url, path, scheme})
(:SSLCertificate {fingerprint, issuer, subject, valid_from, valid_to})
(:MalwareFamily {name, first_seen, technique_tags})
(:Campaign {name, description, first_seen, threat_actor})
(:ThreatActor {name, aliases, origin_country})
(:Vulnerability {cve_id, cwe_id, cvss_score, description})
(:Case {case_number, status, investigation_date})
```

**Relationship Types:**
```
(APK)-[:COMMUNICATES_WITH]->(Domain)
(APK)-[:COMMUNICATES_WITH]->(IPAddress)
(APK)-[:BELONGS_TO]->(MalwareFamily)
(APK)-[:EXPLOITS]->(Vulnerability)
(Domain)-[:RESOLVES_TO]->(IPAddress)
(Campaign)-[:USES]->(Domain)
(Campaign)-[:USES]->(IPAddress)
(ThreatActor)-[:OPERATES]->(Campaign)
(Case)-[:CONTAINS]->(APK)
(APK)-[:RELATED_TO]->(APK)
```

### 9.3 ChromaDB Collections

| Collection | Content | Use Case |
|---|---|---|
| `malware_behavior_embeddings` | Behavioral profile vectors | Similarity search for family attribution |
| `investigation_report_embeddings` | Past report chunks | RAG for Officer Co-Pilot queries |
| `threat_narrative_embeddings` | Narrative text chunks | Similar investigation retrieval |
| `ioc_pattern_embeddings` | IOC pattern vectors | Pattern-based malware grouping |

---

## 10. Frontend & Presentation Plan

### 10.1 React Application Structure

```
frontend/
├── src/
│   ├── pages/
│   │   ├── Dashboard.jsx          # Main investigator dashboard
│   │   ├── CaseUpload.jsx         # APK upload interface
│   │   ├── CaseDetail.jsx         # Full case analysis view
│   │   ├── GraphExplorer.jsx      # Interactive threat graph
│   │   ├── CoPilot.jsx            # Officer Co-Pilot chat
│   │   └── Reports.jsx            # Report download center
│   ├── components/
│   │   ├── ThreatScore.jsx        # Visual risk gauge
│   │   ├── BehaviorTimeline.jsx   # D3.js event timeline
│   │   ├── NetworkGraph.jsx       # D3.js network flow
│   │   ├── PermissionMatrix.jsx   # Permission risk table
│   │   ├── IOCTable.jsx           # Exportable IOC list
│   │   └── VulnerabilityCard.jsx  # CVSS-rated vuln display
```

### 10.2 Key Dashboard Views

**Main Dashboard:**
- Active cases count, threat distribution pie chart
- Recent activity feed with timestamps
- Pending analysis queue with progress bars
- Quick upload button with drag-and-drop APK area

**Case Detail View:**
- Phase-by-phase result tabs (Static | Dynamic | C2 | Vuln | Attribution | Report)
- Composite threat score gauge (0–100)
- IOC table with export buttons (CSV, JSON, STIX)
- Evidence timeline: from upload to completed report

**Graph Explorer:**
- Full-screen D3.js force-directed graph of C2 infrastructure
- Click nodes to expand relationships
- Filter by node type (Domain, IP, APK, Campaign)
- Export as SVG or PNG for reports

**Officer Co-Pilot:**
- Chat interface with streaming LLM responses
- Pre-loaded investigation context for each case
- Suggested questions for investigators
- Citation display: LLM answers linked to evidence

### 10.3 Report Template Design

Each PDF report generated includes the following sections:

```
1. Cover Page
   - Case number, classification, date, analyst
   
2. Executive Summary (1 page)
   - Threat verdict, risk score, key findings
   
3. APK Profile
   - Package name, permissions, certificate info
   
4. Static Analysis Findings
   - Suspicious APIs, IOCs, YARA matches
   
5. Dynamic Behavior Analysis
   - Runtime actions, network communications
   
6. C2 Infrastructure Map
   - Graph image + domain/IP table
   
7. Vulnerability Assessment
   - CVSS-scored findings, OWASP categories
   
8. Attribution & Family Classification
   - Malware family, campaign links, confidence

9. Threat Narrative (AI-Generated)
   - Plain language investigation summary

10. Evidence Inventory
    - All artifacts with SHA256 hashes

11. Chain of Custody
    - Timestamped action log

12. Section 65B Certificate
    - Legal compliance certification

Appendices:
- Full IOC list
- Raw permission declarations
- Audit log export
```

---

## 11. Security & Compliance Plan

### 11.1 Air-Gapped Deployment Architecture

```
CID INTERNAL NETWORK (Air-Gapped)
├── Analysis Server (GPU-enabled)
│   ├── Llama 3 (local inference)
│   ├── FastAPI backend
│   └── Android VM hypervisor
├── Database Server
│   ├── PostgreSQL
│   ├── Neo4j
│   └── ChromaDB
├── Web Server
│   └── React frontend (nginx)
└── Storage Server
    └── Encrypted evidence repository
```

### 11.2 Section 65B Evidence Package Contents

```
section_65b_package_[case_id]_[timestamp].zip (signed)
├── evidence_certificate.pdf        # Section 65B certificate
├── chain_of_custody.json           # Complete audit trail
├── sha256_manifest.json            # All file hashes
├── apk_original.apk                # Original submitted APK
├── static_analysis/
│   ├── decompiled.zip
│   ├── static_report.json
│   └── ioc_list.json
├── dynamic_analysis/
│   ├── network_traffic.pcap
│   ├── api_trace.json
│   └── runtime_behavior.json
├── reports/
│   ├── investigation_report_EN.pdf
│   ├── investigation_report_KN.pdf
│   ├── investigation_report_HI.pdf
│   ├── investigation_report_TA.pdf
│   └── investigation_report_TE.pdf
└── package_signature.sig           # Cryptographic signature
```

### 11.3 RBAC Role Definitions

| Role | Permissions |
|---|---|
| **Investigator** | Submit APKs, view own case reports, use Co-Pilot for own cases |
| **Analyst** | All Investigator + full analysis access, graph exploration, cross-case view |
| **Supervisor** | All Analyst + evidence approval, team case oversight, evidence package release |
| **Administrator** | All + user management, system configuration, audit log access |

### 11.4 Cryptographic Integrity Chain

```
APK Submitted
     ↓
SHA256(apk.file) → stored in PostgreSQL + evidence certificate
     ↓
SHA256(static_report.json) → stored in manifest
     ↓
SHA256(dynamic_analysis/*) → stored in manifest
     ↓
SHA256(investigation_report_EN.pdf) → stored in manifest
     ↓
HMAC-SHA256(sha256_manifest.json, system_key) → package signature
     ↓
All packaged as Section 65B evidence ZIP
```

---

## 12. Testing & Validation Plan

### 12.1 Test APK Samples

| Sample | Type | Testing Purpose |
|---|---|---|
| BankBot variant | Banking trojan | C2 detection, credential theft detection |
| SpyNote RAT | Remote Access Trojan | Runtime monitoring, C2 attribution |
| Cerberus dropper | Dropper malware | Dynamic loading detection, obfuscation detection |
| Joker malware | Subscription fraud | Permission abuse, SMS interception detection |
| Custom benign APK | Control sample | False positive rate measurement |

### 12.2 Test Scenarios

**Functional Tests:**
- [ ] APK upload → static analysis completes within 5 minutes
- [ ] Dynamic sandbox: APK executes and behavioral trace captured
- [ ] C2 graph: known C2 domain appears as node within Neo4j
- [ ] Vulnerability scanner detects hardcoded API key in test APK
- [ ] Attribution engine correctly classifies BankBot sample
- [ ] Multilingual report generates all 5 language PDFs
- [ ] Section 65B package: SHA256 manifest matches all artifacts
- [ ] Officer Co-Pilot responds to "What does this APK steal?" in plain language

**Performance Targets:**
| Metric | Target |
|---|---|
| APK analysis total time | < 30 minutes end-to-end |
| Static analysis phase | < 5 minutes |
| Dynamic analysis phase | < 10 minutes |
| C2 graph construction | < 3 minutes |
| Report generation (all languages) | < 5 minutes |
| Co-Pilot response time | < 10 seconds |

**Security Tests:**
- [ ] RBAC: Investigator cannot access another officer's case
- [ ] Evidence integrity: SHA256 mismatch detected on file tampering
- [ ] No external network calls from air-gapped deployment
- [ ] Section 65B certificate rejected if chain-of-custody broken

---

## 13. Team Roles & Responsibilities

| Role | Area of Responsibility |
|---|---|
| **Team Lead / Architect** | Overall architecture design, LangGraph agent pipeline, system integration |
| **Backend Engineer (Analysis)** | Static analysis engine, dynamic sandbox orchestration, FastAPI endpoints |
| **Backend Engineer (Intelligence)** | Neo4j graph schema, GNN attribution model, ChromaDB integration |
| **AI / LLM Engineer** | Llama 3 deployment, LangChain RAG pipeline, threat narrative prompts, Co-Pilot |
| **Frontend Engineer** | React dashboard, D3.js visualizations, Officer Co-Pilot UI |
| **Security & Compliance Engineer** | Section 65B compliance, RBAC implementation, cryptographic integrity, audit logging |
| **QA / Testing Engineer** | Test APK preparation, integration testing, performance benchmarking |

---

## 14. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Llama 3 inference too slow on CPU-only hardware | Medium | High | Pre-quantize model (GGUF Q4), optimize context window, use smaller model variant |
| Android-x86 VM malware evasion (anti-sandbox detection) | High | Medium | Emulate real device fingerprint, disable VM-detection indicators, use hardware-based sandbox |
| Neo4j graph queries slow on large datasets | Low | Medium | Index all node properties, use Neo4j GDS library, limit traversal depth |
| Multilingual translation quality for Kannada/Tamil | Medium | Medium | Use IndicTrans2 model, manual spot-check of critical report sections |
| YARA false positives on benign apps | Medium | Low | Tune YARA rules with benign corpus, require multi-indicator confirmation for alerts |
| mitmproxy certificate pinning bypass failure | Medium | Medium | Use Frida-based pinning bypass scripts (Universal Android SSL Pinning Fix) |
| APK submitted is packed/encrypted | High | Medium | Add packer detection step, use dynamic analysis as primary for packed APKs |
| Section 65B compliance gap | Low | Critical | Legal review of generated certificates, align with IT Act 2000 Section 65B checklist |

---

## 15. Deliverables Checklist

### Minimum Viable Deliverables (Hackathon Day)

- [ ] **Working APK upload and analysis pipeline** (Phases 1 + 2)
- [ ] **C2 Intelligence Graph** visible in Neo4j (Phase 3)
- [ ] **Vulnerability Discovery Report** with at least 3 OWASP categories (Phase 4)
- [ ] **AI-generated threat narrative** (Phase 5)
- [ ] **PDF investigation report** in English (Phase 6)
- [ ] **React dashboard** showing case overview and findings
- [ ] **Officer Co-Pilot** chat interface (basic Q&A)
- [ ] **Section 65B evidence package** with SHA256 manifest

### Bonus Deliverables (Innovation Points)

- [ ] **All 5 language reports** (EN, KN, HI, TA, TE)
- [ ] **Interactive D3.js C2 infrastructure graph**
- [ ] **Behavior timeline visualization**
- [ ] **Threat scoring dashboard** with risk gauge
- [ ] **IOC export** (CSV, JSON, STIX format)
- [ ] **Historical case correlation** (if multiple samples available)
- [ ] **Air-gapped deployment** demonstrated on isolated network

---

## 16. Success Metrics & KPIs

| Metric | Definition | Target |
|---|---|---|
| **Analysis Completeness** | % of analysis phases completing without manual intervention | > 90% |
| **Threat Detection Rate** | % of known malicious APKs flagged correctly | > 85% |
| **False Positive Rate** | % of benign APKs incorrectly flagged | < 10% |
| **IOC Extraction Accuracy** | % of known IOCs extracted from test samples | > 80% |
| **Attribution Accuracy** | % of malware family classifications matching ground truth | > 75% |
| **Report Generation Time** | Time from analysis complete to multilingual PDFs ready | < 5 minutes |
| **Co-Pilot Response Quality** | Human-rated relevance score for investigative Q&A | > 4/5 |
| **Evidence Package Integrity** | % of packages with valid cryptographic signature | 100% |
| **End-to-End Pipeline Time** | Total time: APK upload → Section 65B package ready | < 30 minutes |

---

*Document Version: 1.0 | Classification: CIDE Hackathon 2026 Submission*
*Institution: R V College of Engineering, Bengaluru | Date: June 2026*

---

> **Note to Reviewers:** This project plan was designed to satisfy all four Feature Areas and Core Platform Requirements as specified in the CIDE Hackathon 2026 brief. All bonus innovation features (AI-Assisted Behavioral Summaries, Threat Scoring, IOC Extraction, Advanced Visualizations, Threat Intelligence Integration) are explicitly planned within Weeks 9–10 of the implementation roadmap. The architecture, agent design, and data layer have been engineered specifically to meet the requirements of an APK investigation and threat analysis platform — not merely a parser or scanner.
