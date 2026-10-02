# APEX-X — Additional Features Implementation Plan

**Purpose of this document:** This is a build spec for seven new capabilities to add to the existing APEX-X codebase, written for CID Karnataka's cybercrime investigation use case. It assumes the reader (human or AI coding agent) has the current repository checked out and is familiar with its layout. Every section names exact files to create or modify, exact function signatures to add, and exactly where each new piece hooks into the pipeline that already exists.

**How to use this doc:** Each feature is self-contained enough to implement independently, but Section 9 (Build Order) explains the dependency chain — some features are much more valuable built on top of others. Start there if you're deciding what to build first.

---

## 0. Baseline: what already exists (do not rebuild this)

Before touching anything, this is the current pipeline these features plug into:

```
Upload (routes/upload.py)
  -> Case created in Postgres (models/database.py: Case, PhaseResult, EvidenceRecord)
  -> Celery task queued (services/task_service.py: analyze_apk_task)
      -> engines/static/__init__.py: run_full_static_analysis()
           steps: apktool_wrapper -> jadx_wrapper -> androguard_analyzer
                  -> manifest_parser -> yara_scanner -> ioc_extractor
                  -> risk_scorer.compute_static_risk()
         writes: <case_dir>/static_analysis/static_report.json
                 <case_dir>/static_analysis/ioc_list.json
      -> engines/dynamic/__init__.py: run_full_dynamic_analysis() (needs a real emulator)
      -> engines/vulnerability/__init__.py: run_vulnerability_scan()
           owasp_scanner.py -> cwe_mapper.py -> cvss_calculator.py -> poc_generator.py
      -> engines/c2/graph_builder.py: build_c2_graph() (writes to Neo4j, uses MERGE
         so identical domain/IP nodes are already shared across cases — but nothing
         surfaces that sharing to a human today)
      -> engines/intelligence/threat_reasoner.py: generate_threat_narrative()
         (uses engines/intelligence/llm_client.py -> local Ollama,
          models: qwen2.5-coder:7b-instruct-q4_K_M and whiterabbitneo,
          config in app/config.py: OLLAMA_MODEL_CODER / OLLAMA_MODEL_SECURITY)
  -> Results served via routes/results.py, reports via routes/reports.py
  -> Frontend renders via frontend/src/app/cases/[id]/*.tsx and
     frontend/src/components/{IOCTable,NetworkGraph,VulnerabilityCard,RecentAlerts}.tsx
```

Key architectural facts to respect:
- All LLM calls MUST go through `engines/intelligence/llm_client.py` (local Ollama only — see the "Local-Only LLM Policy" in `APEX-X_Team_Work_Division.md`). Do not call any cloud LLM API for these features, even though `routes/copilot.py` currently does (that's a pre-existing bug to fix separately, not a pattern to copy).
- `_llm_lock` in `llm_client.py` enforces one model in memory at a time (16GB RAM constraint). Any new feature that calls the LLM must go through `generate()` or `generate_streaming()`, never load a model directly.
- Static engine steps are designed to degrade gracefully — each step is wrapped in try/except and failure of one step doesn't stop the pipeline (see `run_full_static_analysis` in `engines/static/__init__.py`). New steps must follow this same pattern.
- Every phase writes its own JSON report file into `<case_dir>/<phase_name>/`. New features should follow this convention so the reporting/evidence-packaging layer (`apex_x/reporting/`) keeps working without modification.

---

## 1. Cross-case syndicate correlation

### What it does
After a case finishes static analysis (and C2 graph building), automatically checks whether this APK shares infrastructure or identity indicators with any *previously analyzed* case, and if so, surfaces a "possible same operation" alert with the linked case IDs and the specific shared indicator.

### Difficulty it addresses
Fraud rings rename and re-skin the same app repeatedly ("LoanFast" becomes "QuickCash" becomes "RupeeNow"). Each report lands as an unrelated case at a different station. Nothing in the current system actively tells an officer these are connected — the Neo4j graph has the raw data (via `MERGE`) but nothing queries it for cross-case overlap.

### Where it hooks in
New step appended after C2 graph construction in `services/task_service.py`, inside `analyze_apk_task`, right after the existing `build_c2_graph(...)` call.

### New files
**`backend/app/engines/c2/correlation_engine.py`**
```python
def find_correlated_cases(case_id: str, apk_hash: str) -> Dict[str, Any]:
    """
    Queries Neo4j for other Case nodes connected to this case's APK node
    via shared Domain, IPAddress, URL, or (new) SigningCert / BaaSProject / UpiId nodes.
    Returns: {
        "correlated_cases": [
            {"case_id": ..., "case_number": ..., "shared_indicators": [
                {"type": "domain", "value": "..."},
                {"type": "signing_cert", "value": "..."}
            ], "match_strength": "high" | "medium" | "low"}
        ]
    }
    """
```
Cypher query shape (2-hop from this case's APK node to any other Case's APK node via a shared indicator node):
```cypher
MATCH (thisCase:Case {case_id: $case_id})-[:CONTAINS]->(a1:APK)
MATCH (a1)-[:COMMUNICATES_WITH|SIGNED_WITH|USES_BACKEND|PAYS_TO]->(indicator)
MATCH (indicator)<-[:COMMUNICATES_WITH|SIGNED_WITH|USES_BACKEND|PAYS_TO]-(a2:APK)
MATCH (otherCase:Case)-[:CONTAINS]->(a2)
WHERE otherCase.case_id <> $case_id
RETURN otherCase, indicator, labels(indicator)
```

### Data model changes
- **Neo4j:** new node labels `SigningCert {fingerprint}`, `BaaSProject {provider, project_id}`, `UpiId {vpa}` (these are created by Features 2 and 4 below — this feature only *reads* them).
- **Neo4j relationship types:** `SIGNED_WITH` (APK -> SigningCert), `USES_BACKEND` (APK -> BaaSProject), `PAYS_TO` (APK -> UpiId).
- **Postgres:** add a `phase = "correlation"` row type to `phase_results` (no schema change needed, `PhaseResult.phase` is already a free-text string).

### API additions
`GET /api/v1/cases/{case_id}/correlations` in `routes/results.py` — returns the `correlated_cases` list for display.

### Frontend integration
New component `frontend/src/components/SyndicateAlert.tsx` — a banner shown at the top of `frontend/src/app/cases/[id]/OverviewTab.tsx` when `correlated_cases` is non-empty: *"This case shares infrastructure with 2 other cases — possible same operation."* Clicking expands to show the shared indicator and links to the other case IDs.

### Tech stack
Neo4j (already provisioned), Python `neo4j` driver (already a dependency in `graph_builder.py`). No new library needed.

### Depends on
Features 2 (financial indicators) and 4 (fingerprinting) populate the richer node types this feature correlates on. It still works day one using only the existing Domain/IP/URL nodes — those two features just make matches catch repackaged apps that changed their C2 domain but reused a signing cert or UPI ID.

---

## 2. Financial-indicator extraction (UPI IDs, bank accounts, wallets)

### What it does
Extends IOC extraction to specifically pull out UPI VPAs, bank account + IFSC pairs, and crypto wallet addresses from decompiled code and strings — the indicators that actually let police freeze money, as opposed to security-researcher indicators like IPs and API keys.

### Difficulty it addresses
Current `ioc_extractor.py` finds URLs/IPs/domains/emails/API keys/crypto wallets — but has no concept of UPI IDs or Indian bank account/IFSC pairs, which is what an officer needs first in a financial-fraud case (loan apps, investment-scam apps) to send a freeze request before the money moves through mule accounts.

### Where it hooks in
Directly extends the existing extractor rather than creating a parallel system.

### File to modify
**`backend/app/engines/static/ioc_extractor.py`** — add new regex patterns alongside the existing `BTC_REGEX`, `ETH_REGEX`, etc.:
```python
# UPI Virtual Payment Address: username@bankhandle
UPI_REGEX = re.compile(
    r'\b[a-zA-Z0-9.\-_]{2,256}@(?:okhdfcbank|oksbi|okicici|okaxis|ybl|paytm|apl|ibl|axl|'
    r'upi|axisbank|icici|hdfcbank|sbi|kotak|yesbank|freecharge|jio)\b', re.IGNORECASE
)

# Indian bank account number (9-18 digits, contextual — pair with IFSC nearby)
IFSC_REGEX = re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b')
BANK_ACCOUNT_REGEX = re.compile(r'\b\d{9,18}\b')
```
Add a new aggregation key `"financial_indicators"` to the `aggregated` dict in `extract_iocs_from_file()` and `extract_iocs_from_directory()`, structured as:
```python
{
  "upi_ids": [...],
  "ifsc_bank_pairs": [{"ifsc": "...", "account_near": "...", "source_file": "..."}],
  # existing crypto_wallets key is reused, not duplicated
}
```
Bank account numbers are pure digit strings with a very high false-positive rate on their own — only report a `BANK_ACCOUNT_REGEX` hit as a finding when an `IFSC_REGEX` match exists within 100 characters in the same file (pass a window, not a whole-file scan, to keep this precise).

### Where results flow next
`engines/static/__init__.py` already aggregates whatever keys `ioc_extractor` returns into `ioc_results` — no change needed there beyond confirming the new keys pass through. Then wire it into scoring:

**`backend/app/engines/static/risk_scorer.py`** — `_score_iocs()` should treat any non-empty `upi_ids` or `ifsc_bank_pairs` as a high-severity signal (financial fraud apps overwhelmingly hardcode or fetch a payment target), separate from the generic IOC count.

### API additions
No new endpoint — this flows through the existing `GET /api/v1/cases/{id}/results` static payload under `ioc_list.json` -> `financial_indicators`.

### Frontend integration
Extend `frontend/src/components/IOCTable.tsx` with a new filterable category "Financial" (UPI / Bank / Wallet) alongside the existing URL/IP/Domain filters. Add a one-click "Copy freeze-request block" button that formats the UPI ID / account+IFSC into the plain-text block officers paste into a bank/NPCI freeze request.

### Tech stack
Pure Python `re` — no new dependency.

### Depends on
Nothing. This is the simplest, highest-value, build-first feature.

---

## 3. BaaS-as-C2 detector (Firebase / Supabase abuse)

### What it does
Detects when an app uses Firebase Realtime Database, Firestore, or Supabase as its command-and-control / data-exfiltration channel (a documented pattern in real Indian banking trojans this year), extracts the exposed project ID / JWT / API key, and — read-only — queries the exposed endpoint to estimate how many victims' data is sitting in that backend.

### Difficulty it addresses
Modern Android banking trojans increasingly skip traditional C2 servers and just write stolen SMS/card data straight into a Firebase or Supabase project using a hardcoded key. Generic IOC/YARA scanning doesn't know to look at this as C2 infrastructure — it just sees "a URL" and "an API key" as unrelated findings; nobody connects them into "this app is exfiltrating to backend X where 400+ victims' data may already sit."

### Where it hooks in
New static sub-step, runs after `ioc_extractor` inside `run_full_static_analysis()` in `engines/static/__init__.py`, since it needs the same decompiled directories.

### New file
**`backend/app/engines/static/baas_detector.py`**
```python
FIREBASE_URL_REGEX = re.compile(r'https://([a-z0-9\-]+)\.firebaseio\.com')
FIREBASE_PROJECT_REGEX = re.compile(r'"project_id"\s*:\s*"([a-z0-9\-]+)"')
SUPABASE_URL_REGEX = re.compile(r'https://([a-z0-9]+)\.supabase\.co')
JWT_REGEX = re.compile(r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')

def detect_baas_backends(scan_dirs: List[str]) -> Dict[str, Any]:
    """
    Scans decompiled source for Firebase/Supabase endpoint + credential pairs.
    Returns: {"backends": [{"provider": "firebase"|"supabase", "project_id": "...",
                             "endpoint": "...", "credential": "...", "source_file": "..."}]}
    Does NOT make network calls itself — see enrich_baas_exposure() below,
    which is separate and explicitly opt-in (air-gapped deployments must skip it).
    """

def enrich_baas_exposure(backend: Dict[str, Any], allow_network: bool) -> Dict[str, Any]:
    """
    OPTIONAL, only runs if allow_network=True (a case-level setting, defaulting to False
    for air-gapped deployments). Makes a read-only GET to the Firebase/Supabase REST
    endpoint using the extracted key, and reports:
      - whether the endpoint is publicly readable with this credential (a security
        finding in itself — the attacker's own backend is often left open)
      - approximate record count / field names found (NOT full victim data — count
        and schema only, to avoid the tool itself handling live victim PII beyond
        what's needed to size the exposure)
    """
```
This mirrors the real McAfee research pattern (JWT exposed in app code -> query Supabase REST API -> count infected devices) but scoped down: count and schema only, never bulk-download victim PII into APEX-X's own storage. That distinction matters for both legal handling of evidence and for not turning the tool itself into a place holding unredacted victim data.

### Data model changes
- **Neo4j:** new node label `BaaSProject {provider, project_id}`, relationship `APK -[:USES_BACKEND]-> BaaSProject`. This is what Feature 1's correlation query reads.
- **Postgres:** no schema change — findings live inside the existing `PhaseResult.result` JSON blob for the static phase, under a new `baas_findings` key.

### Config additions
**`backend/app/config.py`** — add:
```python
ALLOW_BAAS_NETWORK_ENRICHMENT: bool = os.getenv("ALLOW_BAAS_NETWORK_ENRICHMENT", "false").lower() == "true"
```
Defaults to off, so a genuinely air-gapped CID deployment never makes an outbound call; an internet-connected triage deployment can opt in.

### API / frontend
Surfaces as a new finding card in the existing case detail C2 tab, alongside the network graph — label it "Cloud backend used as C2" with the provider, project ID, and (if enrichment ran) an estimated exposed-record count.

### Tech stack
`httpx` (already a dependency via `llm_client.py`) for the optional enrichment call. No new library.

### Depends on
Nothing to build first, but feeds Feature 1's correlation graph once the `BaaSProject` node type exists.

---

## 4. Repackage / MO fingerprinting (survives rebranding)

### What it does
Computes a fuzzy structural fingerprint of an APK — based on things that don't change when a gang renames the app and changes its icon — so APEX-X can flag "this is structurally the same app as a case from last month" even when the SHA256 hash, package name, and app label are all different.

### Difficulty it addresses
SHA256-based blocking and even the domain/IP correlation in Feature 1 both break the moment the operators do a cosmetic repackage — which the research shows happens routinely ("by the time one network is blocked, another surfaces"). This feature is what makes Feature 1 resilient to that evasion.

### Where it hooks in
New step at the end of `run_full_static_analysis()` in `engines/static/__init__.py`, after `androguard_analyzer` has already produced class/method lists (reuse its output rather than re-parsing the APK).

### New file
**`backend/app/engines/static/fingerprint_engine.py`**
```python
def compute_structural_fingerprint(androguard_data: Dict, apktool_dir: str) -> Dict[str, Any]:
    """
    Builds a fingerprint resistant to cosmetic repackaging, made of:
      1. permission_set_hash: sha256 of the sorted permission list
      2. class_shape_hash: sha256 of sorted (package_depth, method_count_bucket)
         tuples per class — NOT class names (those get renamed/obfuscated),
         just the shape of the class tree
      3. resource_hash_overlap: set of sha256 hashes of non-trivial resource
         files (res/raw, res/drawable) — logos get swapped but shared libraries,
         sound files, or config assets often don't
      4. api_call_signature: sorted set of suspicious API call categories used
         (from androguard_data["api_calls"]) — the *behavior* shape
    Returns: {"fingerprint_id": <sha256 of the 4 hashes combined>,
              "components": {...4 hashes above...}}
    """

def similarity_score(fp_a: Dict, fp_b: Dict) -> float:
    """
    Weighted Jaccard-style similarity across the 4 components (0.0-1.0).
    Used to rank "how confident is this repackage match" rather than a
    binary yes/no, since class-shape and resource overlap are inherently fuzzy.
    """
```
Keep this rule-based and hash/set-based, deliberately — no ML model, no training data needed, and it runs in well under a second per APK, which matters given the 16GB RAM budget is already committed to the LLM.

### Data model changes
- **Postgres:** new table `apk_fingerprints`:
```python
class ApkFingerprint(Base):
    __tablename__ = "apk_fingerprints"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
    fingerprint_id = Column(String(64), index=True)
    permission_set_hash = Column(String(64))
    class_shape_hash = Column(String(64))
    resource_hashes = Column(JSON)   # list, for overlap comparison
    api_call_signature = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
```
Add to `models/database.py`. Index `fingerprint_id` for fast exact-match lookups; similarity-ranked matches require a linear scan over the case table, which is fine at the case volumes a state cyber cell handles (hundreds to low thousands, not millions).

### Integration with Feature 1
After computing the fingerprint, query `apk_fingerprints` for the top-N most similar existing cases (`similarity_score > 0.7` threshold, tunable) and feed any hits into the same `correlated_cases` structure Feature 1 returns, tagged `"match_type": "structural"` vs `"match_type": "infrastructure"` so the frontend can distinguish "same code, evaded via rebrand" from "same C2, different code."

### Tech stack
Pure Python (`hashlib`, set operations). No new dependency.

### Depends on
Reuses Feature 1's alert UI. Should be built after Feature 1's data plumbing exists, even though the fingerprinting logic itself is independent.

---

## 5. Modus-operandi (MO) classifier with suggested legal sections

### What it does
Instead of only a 0-100 numeric risk score, matches the case's static findings against a small library of named, recognizable fraud patterns ("instant loan app harassment," "screen-share remote-access fraud," "investment/task-scam app"), and attaches the IT Act / BNS sections typically applicable to that pattern plus a plain-language summary — reducing the manual translation step from "technical finding" to "chargesheet language."

### Difficulty it addresses
The project's own gap analysis names "poor explainability" as a core problem non-specialist officers face. A risk score alone doesn't tell an officer what crime this is or what to charge; deciding that today is a manual, officer-dependent step.

### Where it hooks in
Runs after both `run_full_static_analysis()` and `run_vulnerability_scan()` complete (it needs OWASP findings too), as a new step added in `services/task_service.py`, following the same pattern as the existing call to `threat_reasoner.generate_threat_narrative()`.

### New file
**`backend/app/engines/intelligence/mo_classifier.py`**
```python
# Deterministic signature table — rule-based, same pattern as owasp_scanner.py
MO_SIGNATURES = [
    {
        "mo_id": "loan_app_harassment",
        "name": "Instant loan app harassment",
        "requires": {
            "permissions_any": ["READ_CONTACTS", "READ_SMS", "CAMERA"],
            "financial_indicators_present": True,   # from Feature 2
            "manifest_flags_any": ["backup_enabled"],
        },
        "legal_sections": ["BNS 316(2) - Criminal breach of trust",
                            "IT Act 66D - Cheating by personation",
                            "IT Act 66E - Violation of privacy"],
        "summary_template": "This app matches the loan-app harassment pattern: "
                             "it harvests contacts/photos beyond any lending need and "
                             "hardcodes a repayment target ({upi_or_account})."
    },
    {
        "mo_id": "remote_access_scam",
        "name": "Screen-share / remote-access fraud",
        "requires": {
            "permissions_all": ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
            "bundled_remote_sdk": True,   # from Feature 6
        },
        "legal_sections": ["IT Act 66C - Identity theft",
                            "IT Act 66D - Cheating by personation",
                            "BNS 318 - Cheating"],
        "summary_template": "This app matches the remote-access scam pattern: it "
                             "requests Accessibility Service and overlay permissions "
                             "and bundles a remote-desktop SDK ({sdk_name})."
    },
    {
        "mo_id": "investment_task_scam",
        "name": "Investment / task-based scam app",
        "requires": {
            "financial_indicators_present": True,
            "iocs_domain_age_or_count": "high_ioc_count",
        },
        "legal_sections": ["BNS 318 - Cheating", "SEBI Act violations (if applicable)"],
        "summary_template": "This app matches the investment/task-scam pattern..."
    },
]

def classify_mo(static_report: Dict, vuln_report: Dict) -> List[Dict[str, Any]]:
    """
    Rule-based matching against MO_SIGNATURES (mirrors owasp_scanner.py's approach —
    no LLM call needed for the match itself). Returns list of matched MOs with
    confidence ("all requires met" vs "partial match").
    """

def narrate_mo_match(mo_match: Dict, case_context: Dict) -> str:
    """
    Only this step touches the LLM — fills in summary_template with actual case
    values via llm_client.generate(), using MODEL_SECURITY (whiterabbitneo) since
    this is a security-narrative task, matching the existing model-selection split.
    Keep the prompt strictly template-filling, not open narrative generation,
    to avoid hallucinated specifics in something that may end up in a legal document.
    """
```
Keeping detection rule-based and only using the LLM for filling in a fixed template (never for the classification decision itself) matters for evidentiary reliability — the "why was this flagged" answer must be a deterministic rule an officer or defense counsel can inspect, not an LLM's opinion.

### Data model changes
- **Postgres:** `PhaseResult` with `phase="mo_classification"`, result JSON = list of matched MOs. No schema change.

### API additions
`GET /api/v1/cases/{case_id}/mo` — returns matched MOs with legal sections.

### Frontend integration
New card at the top of `OverviewTab.tsx`, above the numeric threat score: a named MO badge (e.g. "Instant loan app harassment — high confidence") with an expandable "suggested legal sections" list. This directly answers the officer's real first question ("what am I looking at") before they see any technical detail.

### Tech stack
No new dependency — reuses `llm_client.py` and the existing Ollama setup (`whiterabbitneo` model per `config.py`).

### Depends on
Feature 2 (financial indicators) and Feature 6 (accessibility/remote-access detector) populate signature inputs this classifier needs. Build the MO table with 2-3 signatures initially and expand it as more MOs are formalized — this is designed to grow as a data table, not a code change, once the initial `classify_mo()` engine exists.

---

## 6. Accessibility-service / remote-access abuse detector

### What it does
Flags the specific *combination* of Accessibility Service + draw-over-other-apps permission + a bundled remote-desktop SDK as a named, distinctive pattern, rather than three unrelated line items buried in a permissions table.

### Difficulty it addresses
"Screen mirroring" and fake "verification" scams talk victims into granting Accessibility Service access or installing a remote-control app, giving the attacker full device control. Generic permission-risk scoring (which is what `risk_scorer.py` currently does) treats each dangerous permission independently and doesn't recognize that this specific trio, together, is the signature of a known and highly damaging scam category.

### Where it hooks in
New static sub-step alongside `manifest_parser` in `run_full_static_analysis()`, since it needs both manifest permission data and a class-name/library scan.

### New file
**`backend/app/engines/static/remote_access_detector.py`**
```python
KNOWN_REMOTE_SDK_SIGNATURES = {
    "com.teamviewer": "TeamViewer QuickSupport SDK",
    "com.anydesk": "AnyDesk SDK",
    "com.teamviewer.quicksupport": "TeamViewer QuickSupport SDK",
    # extendable list — same pattern as YARA_RULES_DIR in yara_scanner.py,
    # could equally be moved to a YARA rule file for consistency with the
    # existing yara_scanner.py convention rather than a hardcoded dict
}

def detect_remote_access_abuse(manifest_data: Dict, apktool_dir: str) -> Dict[str, Any]:
    """
    Checks manifest_data["permissions"] for BIND_ACCESSIBILITY_SERVICE and
    SYSTEM_ALERT_WINDOW together, then scans smali/resource package names in
    apktool_dir against KNOWN_REMOTE_SDK_SIGNATURES.
    Returns: {"flagged": bool, "accessibility_service": bool,
              "overlay_permission": bool, "bundled_sdk": str | None}
    """
```

### Data model changes
None beyond the existing `PhaseResult` JSON blob (adds a `remote_access_findings` key to the static report).

### API / frontend
Surfaces as a distinct high-severity card in the vulnerability tab, separate from the generic permission matrix, labeled with the MO name from Feature 5 when it matches (`remote_access_scam`).

### Tech stack
Pure Python, reuses the existing manifest parser output. No new dependency. Optionally move the SDK signature list into a YARA rule (`backend/app/engines/static/rules/`) for consistency with the existing `yara_scanner.py` convention instead of a hardcoded dict — either works, YARA is preferable if the signature list grows past a handful of entries.

### Depends on
Nothing. Feeds Feature 5.

---

## 7. Bulk intake + auto-triage queue

### What it does
Accepts many APKs at once (e.g., a batch pulled from `cybercrime.gov.in`-style complaints), runs static analysis + risk scoring + the correlation/fingerprint checks on all of them unattended, and returns a ranked queue so an overloaded cyber cell knows which handful out of hundreds deserve an officer's attention today.

### Difficulty it addresses
Malware detections are reported up roughly 400% year over year in the region; a cyber cell cannot deep-dive every complaint one at a time. Every comparable tool (MobSF, Cuckoo, Any.Run) is built around one analyst analyzing one sample in one sitting — there's no existing "triage a pile of 300" workflow to extend, this is new end to end.

### Where it hooks in
New top-level route and a new Celery orchestration entry point, sitting alongside (not replacing) the existing single-case flow in `services/task_service.py`.

### New files
**`backend/app/api/routes/bulk.py`**
```python
@router.post("/bulk-upload")
async def bulk_upload_apks(files: List[UploadFile], db: Session = Depends(...)):
    """
    Accepts multiple APK files in one multipart request. Creates one Case row
    per file (reusing the existing upload.py validation/hash logic — import and
    call its helper functions rather than duplicating them), and enqueues each
    with a *lower* Celery priority than interactively-triggered single-case
    analysis, so an officer who is actively working a case isn't stuck behind
    a 300-file batch job.
    Returns: {"batch_id": ..., "case_ids": [...], "queued": <count>}
    """

@router.get("/bulk/{batch_id}/queue")
async def get_triage_queue(batch_id: str, db: Session = Depends(...)):
    """
    Once all cases in the batch have at least completed static analysis,
    returns a ranked list combining:
      - risk_score (from risk_scorer.py)
      - correlation_boost: +weight if Feature 1 found linked cases (a case that's
        part of a bigger identified operation should outrank an isolated low-risk one)
      - mo_confidence: from Feature 5, "high confidence" matches rank above
        "partial match" or "no MO matched"
    Returns: {"queue": [{"case_id", "case_number", "priority_score",
                          "risk_score", "mo_name", "correlated_case_count"}]}
    ordered highest priority_score first.
    """
```
**`backend/app/services/triage_service.py`**
```python
def compute_priority_score(risk_score: int, correlated_case_count: int,
                            mo_confidence: str) -> float:
    """
    Simple, inspectable weighted formula (not ML) — an officer needs to be able
    to see why case A outranks case B:
      priority = risk_score
               + (correlated_case_count * 15, capped at +45)
               + (30 if mo_confidence == "high" else 10 if "partial" else 0)
    """
```

### Data model changes
- **Postgres:** new table `batches`:
```python
class Batch(Base):
    __tablename__ = "batches"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_by = Column(Integer, ForeignKey("users.id"))
    total_files = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

class BatchCase(Base):
    __tablename__ = "batch_cases"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    batch_id = Column(UUID(as_uuid=True), ForeignKey("batches.id"))
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id"))
```

### Celery / task queue changes
`services/task_service.py` — give `analyze_apk_task` a `priority` kwarg and configure Celery with a low-priority queue (`celery_app.conf.task_routes` or a separate queue name `"bulk_analysis"`) so bulk jobs use idle worker capacity rather than competing with interactive single-case runs. This requires at least 2 Celery worker processes in `docker-compose.yml` (one dedicated to `bulk_analysis` queue with concurrency capped low to protect shared CPU/RAM, since the local LLM steps are memory-heavy).

### Frontend integration
New page `frontend/src/app/dashboard/triage/page.tsx` — a sortable table (reuse the existing `CaseCard.tsx` styling) showing the ranked queue, with the priority score broken down into its three components so an officer can see *why* a case is ranked where it is (transparency matters for something influencing investigative priority).

### Tech stack
No new external dependency — reuses Celery/Redis (already provisioned) and Postgres.

### Depends on
Most valuable once Features 1, 2, and 5 exist (so the ranking has correlation and MO data to use), but the bulk-upload mechanism and a risk-score-only ranking is useful and buildable on day one.

---

## 8. Cross-cutting changes needed regardless of which features you build

### `docker-compose.yml`
No new services required for Features 1-6 (they reuse Postgres/Neo4j/Redis/Ollama already defined). Feature 7 needs a second Celery worker entry:
```yaml
  celery-worker-bulk:
    build: ./backend
    command: celery -A app.services.task_service worker -Q bulk_analysis --concurrency=1
    depends_on: [redis, postgres]
```

### `backend/run_engines.py` (CLI test runner)
Add flags so each feature can be smoke-tested standalone without the full API/DB stack, matching the existing `--static-only` / `--dynamic-only` pattern:
```
--with-correlation      # runs Feature 1 against existing Neo4j data
--with-fingerprint      # runs Feature 4 fingerprinting only
--with-mo-classify      # runs Feature 5 against an existing static_report.json
```

### Database migrations
All new Postgres tables (`apk_fingerprints`, `batches`, `batch_cases`) should be added via whatever migration tool the project already uses for `models/database.py` (check for Alembic config; if none exists yet, that's a prerequisite gap worth flagging separately, since `database.py` currently defines tables with no visible migration history).

### Testing
`backend/tests/` — add one test module per feature (`test_correlation_engine.py`, `test_ioc_extractor_financial.py`, `test_baas_detector.py`, `test_fingerprint_engine.py`, `test_mo_classifier.py`, `test_remote_access_detector.py`, `test_triage_service.py`), each using a small fixture static report JSON rather than a real APK, so tests run in CI without needing APKTool/JADX/an emulator installed.

---

## 9. Suggested build order

For a hackathon-length timeline, build in this order — each step is independently demoable and later steps compound in value:

1. **Feature 2 (financial IOCs)** — half a day, pure regex work extending an existing file, immediately demoable against the existing DIVA/InsecureShop/AndroGoat sample data.
2. **Feature 6 (remote-access detector)** — half a day, same pattern, independent.
3. **Feature 3 (BaaS-as-C2 detector)** — one day, the detection half without network enrichment is straightforward; skip the optional live-query part unless there's time.
4. **Feature 4 (fingerprinting)** — one day, needs the new `apk_fingerprints` table but no new UI beyond what Feature 1 needs.
5. **Feature 1 (syndicate correlation)** — the payoff step; needs at least Feature 2 or 4 to have interesting data to correlate on, plus the Neo4j relationship types they create. Reserve a full day, most of it for the frontend alert UI since that's what judges will actually see.
6. **Feature 5 (MO classifier)** — half a day for 2-3 signatures once Features 2 and 6 exist to feed it.
7. **Feature 7 (bulk triage)** — build last; it's the most infrastructure-heavy (new Celery queue, new tables, new page) and is most convincing once it can rank on real correlation/MO data from the other six.

If time is very short, **Features 2, 6, and 1 alone** already tell a complete, demoable story: "we extract the indicators that matter for financial fraud, we recognize the specific device-takeover pattern used in remote-access scams, and we connect this case to two others that turn out to be the same syndicate." That is the strongest three-feature subset for a live demo.

---

## 10. Tech stack summary (no additions beyond what's already in the project)

| Feature | New Python deps | New JS deps | New infra |
|---|---|---|---|
| 1. Syndicate correlation | none (`neo4j` driver already present) | none | none |
| 2. Financial IOCs | none (`re`, stdlib) | none | none |
| 3. BaaS-as-C2 detector | none (`httpx` already present) | none | none |
| 4. Fingerprinting | none (`hashlib`, stdlib) | none | none |
| 5. MO classifier | none (reuses `llm_client.py`/Ollama) | none | none |
| 6. Remote-access detector | none | none | none |
| 7. Bulk triage | none (Celery/Redis already present) | none | one extra Celery worker process |

Every feature above is designed to be additive to the existing stack precisely so the pitch can honestly claim it fits the "built exclusively with open-source and free tools" and "local, air-gapped LLM" constraints already committed to in the project's own documents.
