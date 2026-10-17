# Changelog

All notable changes to the HawkScan repository will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-17

### Added: HawkScan Autonomous White-Box AI Pentester ("Proof-by-Exploitation")

- **5-Phase Autonomous Pipeline (`hawkscan/`)**:
  - **Phase 1: Static Code Reconnaissance & AST Surface Mapping**: `RepoScanner` and `SurfaceMapper` analyze local source repositories, extract routes across Python frameworks (FastAPI), resolve `APIRouter` prefixes, extract route parameters, and map prioritized attack targets.
  - **Phase 2: Dynamic Reconnaissance & Live Target Session Acquisition**: `DynamicCrawler` discovers live endpoints and authenticates test user sessions (Alice Johnson).
  - **Phase 3: Multi-Agent Parallel Exploitation**: `IdorExploitAgent`, `SqliExploitAgent`, and `MisconfigExploitAgent` execute concurrent non-destructive exploit probes.
  - **Phase 4: Proof-by-Exploitation Validation**: `ProofValidator` enforces the "No Exploit, No Report" doctrine, verifying live working PoCs (HTTP 200/201 + leaked data payload) and filtering unproven theoretical candidates as `DISCARDED_FALSE_POSITIVE`.
  - **Phase 5: Reporting & Artifact Generation**: `SarifGenerator` (OASIS SARIF 2.1.0), `MarkdownGenerator` (executive audit reports with curl PoCs), and `PatchGenerator` (remediation unified git diffs).
- **ApexPortal Corporate Testbed (`target_app/`)**:
  - Enterprise portal on port 8000 with seeded users (`alice@apex.local`, `bob@apex.local`) and confidential M&A financial acquisitions (`REC-9001` $42.5M, `REC-9002` $120k).
  - Unpatched IDOR / BOLA vulnerability in `/api/records/{record_id}`.
  - Unpatched SQL injection flaw in `/api/search?q=...`.
  - Insecure CORS configuration with wildcard origins and credentials enabled.
  - Dynamic runtime security patch toggles (`/api/admin/toggle-patch?feature=idor|sqli|cors`).
- **HawkScan War Room Web UI (`hawkscan/server/static/index.html`)**:
  - Cyber defense war room interface on port 9090.
  - Visual 5-Phase status stepper with live progress animation.
  - Real-time terminal log viewer streaming SSE telemetry events from `/api/stream`.
  - Attack surface map, target application live webview iframe, verified breaches table with reproducible curl commands and JSON evidence payloads, and one-click SARIF / Markdown report export buttons.
- **CLI & Monorepo Launcher**:
  - `launch.py`: Concurrently boots ApexPortal (port 8000) and HawkScan (port 9090), displaying custom `HAWKSCAN` ASCII art, and cleanly tears down process groups on `Ctrl+C`, `Ctrl+Q`, or `'q'`.
  - `hawkscan/cli.py`: Standalone CLI runner (`python3 -m hawkscan.cli start -u ... -r ... -o ...`).
- **Automated Test Suite (`tests/test_hawkscan.py`)**:
  - 10 automated tests covering database initialization, auth, IDOR, SQLi, patch toggling, AST route extraction, Proof Validator false positive suppression, SARIF/Markdown generation, REST API endpoints, full end-to-end pipeline execution, and zero-false-positive proof under active defense (10/10 passed).
- **Architecture Decisions & Governance**:
  - Recorded ADR-0001 through ADR-0005 in `docs/decisions/` and indexed in `docs/DECISIONS.md`.
