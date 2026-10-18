# HawkScan: Autonomous White-Box AI Pentester

```
██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗ ██████╗  █████╗ ███╗   ██╗
██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝██╔════╝ ██╔══██╗████╗  ██║
███████║███████║██║ █╗ ██║█████═╝ ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██╔══██║██║███╗██║██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚███╔███╔╝██║ ╚██╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-13%2F13%20Passing%20(100%25)-brightgreen.svg)](docs/TESTING.md)
[![Standard](https://img.shields.io/badge/SARIF-OASIS%202.1.0-orange.svg)](docs/DATA_MODEL.md)
[![Doctrine](https://img.shields.io/badge/Doctrine-No%20Exploit%2C%20No%20Report-red.svg)](docs/decisions/0002-proof-by-exploitation-doctrine.md)
[![TinyFish](https://img.shields.io/badge/Browser%20Engine-TinyFish%20CDP%20%2B%20Playwright-blueviolet.svg)](docs/decisions/0006-tinyfish-browser-agent-and-cookie-exploitation.md)
[![License](https://img.shields.io/badge/License-Defensive%20Security%20Research-lightgrey.svg)](docs/SECURITY.md)

**Autonomous White-Box AI Pentester · Proof-by-Exploitation ("No Exploit, No Report")**

---

## 1. Overview & Core Philosophy

**HawkScan** is an autonomous white-box artificial intelligence penetration testing agent. Traditional SAST and DAST scanners rely on heuristic regexes and noisy pattern matching, flooding engineering teams with theoretical alerts and false positives.

HawkScan operates on a strict **"Proof-by-Exploitation" ("No Exploit, No Report")** doctrine:
- **White-Box AST Route Reconnaissance**: Analyzes local source code repository to discover web routes, query parameters, data models, and high-probability attack vectors.
- **Dynamic Crawling & Session Acquisition**: Connects to the running application, maps live endpoints, and authenticates legitimate test credentials.
- **Parallel Multi-Agent Exploitation**: Asynchronously deploys specialized exploit agents targeting Broken Object Level Authorization (IDOR / BOLA), SQL Injection (SQLi), CORS reflection, and Cookie Security Flaws.
- **TinyFish Browser Automation & Action Playback Recorder**: Dual-engine browser automation (TinyFish Cloud CDP + Local Playwright Chromium) records chronological step-by-step exploit playback traces and executes client-side JavaScript (`document.cookie`) to verify session theft.
- **Proof-by-Exploitation Validation**: Evaluates exploit attempts against live HTTP response status codes and exfiltrated payloads. **Any theoretical finding that fails live exploitation is suppressed from the verified findings.**
- **Actionable Remediation Artifacts**: Generates standardized OASIS SARIF 2.1.0 schemas, comprehensive Markdown audit reports with reproducible `curl` commands, and Git diff patches.

---

## 2. 5-Phase Architecture Workflow

```mermaid
flowchart TD
    subgraph P1["Phase 1: Static Code Reconnaissance"]
        R1[RepoScanner: AST Route Extractor] --> S1[SurfaceMapper: Attack Surface Map]
    end

    subgraph P2["Phase 2: Dynamic Reconnaissance"]
        C1[DynamicCrawler: Live Target Prober] --> A1[Session Acquisition & Cookie Extraction]
    end

    subgraph P3["Phase 3: Multi-Agent Exploitation & Browser Probing"]
        E1[IdorExploitAgent: BOLA Probes]
        E2[SqliExploitAgent: SQL Syntax Injections]
        E3[MisconfigExploitAgent: CORS Probes]
        E4[CookieExploitAgent: DOM Theft via TinyFish]
        TF[TinyFish Engine: Cloud CDP & Playwright]
        SR[StepRecorder: Action Playback Logs]
    end

    subgraph P4["Phase 4: Proof-by-Exploitation"]
        PV[ProofValidator: No Exploit, No Report]
        PV -->|Breach Proven: HTTP 200 + Leaked Payload| VER[Verified Vulnerabilities]
        PV -->|Defense Active: HTTP 403 / No Breach| DIS[Suppressed False Positives]
    end

    subgraph P5["Phase 5: Reporting & Remediation"]
        VER --> SF[OASIS SARIF 2.1.0]
        VER --> MD[Markdown Audit Report with curl PoCs]
        VER --> PT[Unified Git Diff Patches]
    end

    S1 --> P2
    A1 --> P3
    P3 --> PV
```

---

## 3. Quick Start

### 1. Launch Everything with One Command
The monorepo launcher initializes the target database, starts the ApexPortal testbed on port 8000, starts the HawkScan server on port 9090, and opens the HawkScan War Room UI:

```bash
.venv/bin/python3 launch.py
```

- **HawkScan War Room Web UI**: `http://127.0.0.1:9090`
- **Target Application (ApexPortal)**: `http://127.0.0.1:8000`
- **SARIF 2.1.0 Export**: `http://127.0.0.1:9090/api/export/sarif`
- **Markdown Export**: `http://127.0.0.1:9090/api/export/markdown`
- **SSE Telemetry Feed**: `http://127.0.0.1:9090/api/stream`

*(Press `Ctrl+C`, `Ctrl+Q`, or type `q` to stop all services cleanly.)*

### 2. Run via HawkScan CLI
You can run HawkScan directly from the command line against any target website URL (with an optional local repository path):

```bash
# Pentest any website directly (Target Website Mode)
.venv/bin/python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -o markdown

# Output OASIS SARIF 2.1.0 JSON (with optional source repo)
.venv/bin/python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -r target_app -o sarif
```

---

## 4. Key Capabilities & Exploit Matrix

| Vulnerability Category | Rule ID | Target Endpoint | Exploitation Vector | Verification Proof | Remediation Patch |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Broken Object Level Authorization (IDOR / BOLA)** | `HAWKSCAN-BOLA-001` | `GET /api/records/{id}` | Alice requests Bob Chen's confidential acquisition portfolio (`REC-9001`, $42.5M). | Captures HTTP 200 with `DATA_LEAK_CONFIRMED` and financial valuation data. | Enforces tenancy check (`record.owner_id == current_user.id`) with HTTP 403. |
| **SQL Injection (SQLi)** | `HAWKSCAN-SQLI-001` | `GET /api/search?q={query}` | Concatenates boolean breakout query (`' OR '1'='1`) into unparameterized SQL. | Exfiltrates all multi-tenant records across database boundaries. | Replaces raw SQL interpolation with parameterized SQLAlchemy ORM bindings. |
| **Security Misconfiguration (CORS)** | `HAWKSCAN-CORS-001` | `GET /api/records` | Wildcard origin reflection with credentials enabled (`Origin: https://malicious-attacker.corp`). | Captures reflected origin header alongside `Access-Control-Allow-Credentials: true`. | Restricts CORS whitelist to explicit trusted origins. |

### Dynamic Patch Defense Verification
HawkScan's Phase 4 proof validator guarantees that when defenses are toggled on, HawkScan reports **zero false alarms**:
- **Unpatched State**: 2+ proven breaches reported (`HAWKSCAN-BOLA-001` CRITICAL, `HAWKSCAN-SQLI-001` HIGH).
- **Patched State**: 0 vulnerabilities reported; unverified static patterns are classified under `DISCARDED_FALSE_POSITIVE`.

---

## 5. Sample Output & Remediation Artifacts

### 1. Reproducible Proof-of-Concept (curl)
Every verified breach provides a copy-pasteable command to reproduce the vulnerability instantly:

```bash
curl -X GET 'http://127.0.0.1:8000/api/records/REC-9001' \
  -H 'Authorization: Bearer apex_token_alice_sec_99182' \
  -H 'Accept: application/json'
```

### 2. Leaked Evidence Payload
```json
{
  "id": "REC-9001",
  "owner_id": 2,
  "title": "Q3 Strategic Acquisition & Valuation Portfolio",
  "category": "M&A Financial",
  "confidential_data": "CONFIDENTIAL: Proposed acquisition of FinTech Corp for $42,500,000 USD...",
  "amount": 42500000.0,
  "security_warning": "DATA_LEAK_CONFIRMED"
}
```

### 3. Actionable Remediation Patch (`git apply`)
```diff
--- a/target_app/routes/records.py
+++ b/target_app/routes/records.py
@@ -46,6 +46,12 @@ def get_record_detail(record_id: str, current_user: User = Depends(get_current_u
     if not record:
         raise HTTPException(status_code=404, detail="Record not found")
+
+    # Enforce Object-Level Tenancy Ownership
+    if record.owner_id != current_user.id:
+        raise HTTPException(
+            status_code=403,
+            detail="Access Denied: You do not have permission to view this confidential record"
+        )
+
     return record
```

---

## 6. Automated Test Suite

HawkScan includes an automated test suite covering all 5 phases:

```bash
.venv/bin/python3 -m unittest tests/test_hawkscan.py
```

```
Ran 10 tests in 1.058s - OK (100% Passing)
```

1. `test_01_target_app_db_and_auth`: Database seed integrity & login session acquisition.
2. `test_02_target_app_idor_vulnerability`: Confirms cross-tenant BOLA leak of Bob's record.
3. `test_03_target_app_sqli_vulnerability`: Confirms SQL injection breakout & multi-record exfiltration.
4. `test_04_target_app_patch_toggle`: Verifies dynamic patch toggling and HTTP 403 access denial.
5. `test_05_static_analyzer_repo_scanner`: Phase 1 AST route discovery & router prefix resolution.
6. `test_06_proof_validator_no_exploit_no_report`: Phase 4 Proof Validator suppression logic.
7. `test_07_sarif_and_markdown_generator`: OASIS SARIF 2.1.0 and Markdown artifact formatting.
8. `test_08_hawkscan_server_api_and_ui`: HawkScan REST API endpoints and War Room UI.
9. `test_09_full_pipeline_end_to_end`: Live 5-phase scan against running background testbed.
10. `test_10_patch_toggle_prevents_false_positives`: Verifies zero false alarms under active defense.

---

## 7. Project Directory Layout

```
HawkScan/
├── launch.py                          # Unified monorepo runner (ports 8000 & 9090)
├── README.md                          # Repository overview & quick start
├── docs/                              # Engineering governance & specifications
│   ├── ARCHITECTURE.md                # 5-phase system architecture
│   ├── API.md                         # HawkScan & ApexPortal REST API specs
│   ├── DATA_MODEL.md                  # Database & vulnerability dossier models
│   ├── TESTING.md                     # Test execution & verified results log
│   ├── PROGRESS.md                    # Engineering status log
│   ├── CHANGELOG.md                   # Semantic release history (v1.0.0)
│   ├── SECURITY.md                    # Defensive principles & safety invariants
│   ├── OPERATIONS.md                  # Operations, setup & troubleshooting
│   ├── DECISIONS.md                   # Chronological ADR index
│   └── decisions/                     # Architecture Decision Records (ADRs)
│       ├── 0001-autonomous-whitebox-ai-pentester-architecture.md
│       ├── 0002-proof-by-exploitation-doctrine.md
│       ├── 0003-apexportal-vulnerable-testbed-and-dynamic-patches.md
│       ├── 0004-war-room-ui-and-sse-telemetry.md
│       └── 0005-oasis-sarif-and-remediation-patch-artifacts.md
├── hawkscan/                          # HawkScan Autonomous AI Pentester Core
│   ├── cli.py                         # Standalone CLI runner
│   ├── config.py                      # Port and environment configuration
│   ├── orchestrator/
│   │   └── pipeline.py                # 5-phase durable execution coordinator
│   ├── static_analyzer/
│   │   ├── repo_scanner.py            # Local AST route extractor & prefix resolver
│   │   └── surface_mapper.py          # Trust boundary & target attack surface mapper
│   ├── dynamic_analyzer/
│   │   └── crawler.py                 # Live endpoint crawler & session acquirer
│   ├── agents/
│   │   ├── idor_agent.py              # Cross-tenant BOLA exploit agent
│   │   ├── sqli_agent.py              # SQL injection breakout exploit agent
│   │   ├── misconfig_agent.py         # CORS origin reflection probe
│   │   └── proof_validator.py         # "No Exploit, No Report" proof verifier
│   ├── reporting/
│   │   ├── sarif_generator.py         # OASIS SARIF 2.1.0 generator
│   │   ├── markdown_generator.py      # Executive audit Markdown report generator
│   │   └── patch_generator.py         # Unified Git diff patch generator
│   └── server/
│       ├── app.py                     # FastAPI control plane & SSE streamer
│       └── static/
│           └── index.html             # HawkScan War Room Web UI (Dark theme)
├── target_app/                        # ApexPortal Intentionally Vulnerable Testbed
│   ├── app.py                         # Target FastAPI server (Port 8000)
│   ├── database.py                    # SQLite database & seed data
│   ├── routes/
│   │   ├── auth.py                    # Login & session cookie routes
│   │   ├── records.py                 # Confidential records route (IDOR)
│   │   ├── search.py                  # Search route (SQLi)
│   │   └── admin.py                   # Dynamic patch toggles
│   └── static/
│       └── index.html                 # ApexPortal corporate web app
└── tests/
    └── test_hawkscan.py               # Automated 10-test test suite
```

---

## 8. Documentation Index

For in-depth specifications, consult the documents in [`docs/`](docs/):
- **[System Architecture](docs/ARCHITECTURE.md)**: 5-Phase pipeline design and components.
- **[API Specifications](docs/API.md)**: Control plane REST endpoints, SSE streams, and target application routes.
- **[Data Models & Schemas](docs/DATA_MODEL.md)**: SQLite schemas, SARIF 2.1.0 structures, and patch models.
- **[Testing Strategy & Verification Log](docs/TESTING.md)**: Automated test outputs and operational invariants.
- **[Operations Runbook](docs/OPERATIONS.md)**: Setup, CLI instructions, and troubleshooting.
- **[Security Policy](docs/SECURITY.md)**: Defensive security mission and non-destructive probe invariants.
- **[Engineering Progress Log](docs/PROGRESS.md)**: Implementation progress and component status.
- **[Changelog](docs/CHANGELOG.md)**: Release history and version notes.
- **[Architecture Decision Records (ADRs)](docs/DECISIONS.md)**: Formal architectural choices and trade-off analysis.

---

## 9. Safety & Defensive Principles

HawkScan is engineered strictly for **defensive security auditing** and continuous regression prevention. In accordance with [`AGENTS.md`](AGENTS.md):
- Probes are non-destructive and read-only.
- No destructive SQL or tampering payloads are generated or executed.
- Testing is confined to local environments or systems where explicit written authorization is granted.
