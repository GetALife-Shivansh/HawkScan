# System Architecture: HawkScan Autonomous White-Box AI Pentester

## 1. Executive Architecture

HawkScan is an autonomous white-box artificial intelligence penetration testing framework. HawkScan unifies static repository AST code analysis with parallel dynamic exploitation agents, strictly enforcing the **"Proof-by-Exploitation" ("No Exploit, No Report")** doctrine: a theoretical finding is never included in the verified security findings unless an autonomous agent executes a working Proof-of-Concept against the running application and captures tangible evidence of compromise.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           HAWKSCAN PENTESTER CORE                            │
│                                                                              │
│   ┌───────────────────────────┐          ┌───────────────────────────────┐   │
│   │   Phase 1: Static Recon   │          │    Phase 2: Dynamic Recon     │   │
│   │   - RepoScanner (AST)     │ ───────► │    - DynamicCrawler           │   │
│   │   - SurfaceMapper         │          │    - Live Session Acquisition │   │
│   └───────────────────────────┘          └───────────────────────────────┘   │
│                 │                                        │                   │
│                 ▼                                        ▼                   │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │            Phase 3: Multi-Agent Parallel Exploitation                │   │
│   │   - IdorExploitAgent (BOLA / Broken Object Level Authorization)      │   │
│   │   - SqliExploitAgent (SQL Syntax Breakout & Data Exfiltration)       │   │
│   │   - MisconfigExploitAgent (CORS Wildcard & Credential Reflection)   │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │      Phase 4: Proof-by-Exploitation ("No Exploit, No Report")        │   │
│   │   - ProofValidator: Validates live HTTP 200 PoC & leaked payload      │   │
│   │   - Suppresses unproven theoretical candidates (Zero False Positives)│   │
│   └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌──────────────────────────────────────────────────────────────────────┐   │
│   │               Phase 5: Reporting & Artifact Generation               │   │
│   │   - OASIS SARIF 2.1.0 (`SarifGenerator`)                             │   │
│   │   - Markdown Pentest Report (`MarkdownGenerator`)                    │   │
│   │   - Remediation Git Patches (`PatchGenerator`)                       │   │
│   └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
              ▲                                            │
              │ Live Exploit Probes                        │ Telemetry SSE / JSON
              ▼                                            ▼
┌───────────────────────────────┐            ┌─────────────────────────────────┐
│     ApexPortal Testbed        │            │       HawkScan War Room         │
│   - Port 8000 (Target App)    │            │   - Port 9090 (Web UI & API)    │
│   - Multi-tenant Records      │            │   - 5-Phase Visual Stepper      │
│   - Runtime Patch Toggles     │            │   - Real-time Terminal Stream   │
│   - BOLA & SQLi Endpoints     │            │   - Verified Breaches & PoCs    │
└───────────────────────────────┘            └─────────────────────────────────┘
```

---

## 2. Component Directory & Tech Stack

| Component | Path | Responsibility | Technology |
| :--- | :--- | :--- | :--- |
| **HawkScan Core** | `hawkscan/` | Orchestrates 5-phase pentesting pipeline, static AST scanning, dynamic crawling, multi-agent exploit probes, and proof validation. | Python 3.14, FastAPI, asyncio, httpx, pydantic |
| **Static Analyzer** | `hawkscan/static_analyzer/` | Discovers routes, parameters, ORM calls, and suspicious code patterns from local source files without execution. | Python AST (`ast`), regex |
| **Dynamic Analyzer** | `hawkscan/dynamic_analyzer/` | Connects to running target instance, authenticates test user, maps live HTTP response headers, and discovers endpoints. | httpx (async) |
| **Exploit Agents** | `hawkscan/agents/` | Executes targeted non-destructive exploit payloads (IDOR horizontal tenant leakage, SQL injection syntax breakout, CORS origin reflection). | Python, httpx |
| **Proof Validator** | `hawkscan/agents/proof_validator.py` | Enforces "No Exploit, No Report" rule: discards theoretical findings that failed live exploitation. | Python |
| **Reporting Engine** | `hawkscan/reporting/` | Generates standardized OASIS SARIF 2.1.0, audit Markdown reports, and Git remediation unified diffs. | Python, SARIF 2.1.0 |
| **Control Plane & UI** | `hawkscan/server/` | Serves REST endpoints (`/api/scan/start`, `/api/scan/report`, `/api/export/*`), SSE telemetry stream (`/api/stream`), and War Room UI. | FastAPI, HTML5/CSS3/Vanilla JS |
| **CLI Runner** | `hawkscan/cli.py` | Command-line interface (`hawkscan start -u <url> -r <repo> -o <format>`). | Python argparse |
| **ApexPortal Target App**| `target_app/` | Enterprise corporate portal testbed with pre-seeded database, authentication, confidential acquisition records, and dynamic patch toggles. | FastAPI, SQLite, SQLAlchemy |
| **Monorepo Launcher** | `launch.py` | Single-command orchestrator that concurrently boots target (8000) and HawkScan (9090) with process cleanup on Ctrl+C/Ctrl+Q. | Python subprocess, termios |

---

## 3. The 5-Phase Pipeline Details

### Phase 1: Static Code Reconnaissance & AST Surface Mapping
- `RepoScanner` walks the repository (ignoring `.venv`, `node_modules`, `.git`).
- Parses Python route decorators (`@app.get`, `@router.post`, etc.), extracting HTTP methods, parameterized URL patterns, and function names.
- Analyzes code risk patterns:
  - Raw SQL queries with string concatenation (`WHERE title LIKE '%{q}%'`).
  - Database queries using object IDs without ownership checks (`Record.id == record_id` without `owner_id == user.id`).
  - CORS configurations with wildcard credentials (`allow_origins=["*"]` + `allow_credentials=True`).
- `SurfaceMapper` maps trust boundaries into categorized target endpoints (`public_endpoints`, `authenticated_endpoints`, `object_endpoints`, `search_endpoints`).

### Phase 2: Dynamic Reconnaissance & Session Acquisition
- `DynamicCrawler` verifies live target reachability at target URL (`http://127.0.0.1:8000`).
- Establishes a legitimate test session via `/api/auth/login` (Alice Johnson).
- Extracts session cookies (`apex_session`) and Bearer authentication tokens.
- Cross-references static routes against live HTTP responses to confirm active endpoints.

### Phase 3: Vulnerability Analysis & Parallel Exploitation
- Multiple exploit agents execute asynchronously:
  1. **IdorExploitAgent**: Uses Alice's authenticated session to request foreign object identifiers (e.g. Bob's confidential record `REC-9001`). Checks for cross-tenant data leakage.
  2. **SqliExploitAgent**: Injects safe SQL boolean breakout payloads (`' OR '1'='1`) into query parameters (`/api/search?q=...`) to verify whether record sets from other tenants are exfiltrated.
  3. **MisconfigExploitAgent**: Sends requests with untrusted `Origin` headers to check for insecure CORS reflections with `Access-Control-Allow-Credentials: true`.

### Phase 4: Proof-by-Exploitation Validation ("No Exploit, No Report")
- `ProofValidator` receives raw exploit attempts and static risk flags.
- Validates that:
  - The HTTP response status was successful (HTTP 200).
  - The response payload contained proven leaked confidential data.
  - A clean, reproducible Proof-of-Concept `curl` command was recorded.
- **Any vulnerability that does not meet these criteria is rejected and classified as `DISCARDED_FALSE_POSITIVE`.**

### Phase 5: Reporting & Artifact Generation
- Generates:
  1. **OASIS SARIF 2.1.0** for integration into GitHub Advanced Security, GitLab, or CI/CD pipelines.
  2. **Audit Markdown Report** with executive summary, severity rankings, CWE mappings, exact PoC commands, leaked payloads, and remediation guidance.
  3. **Unified Git Diff Patches** ready to apply via `git apply` to remediate the vulnerable source files.
