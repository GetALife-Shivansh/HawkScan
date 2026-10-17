# Testing Strategy & Verification Log: HawkScan Autonomous AI Pentester

## 1. Test Strategy Overview

HawkScan employs an automated 5-phase testing strategy strictly adhering to the **"Proof-by-Exploitation" ("No Exploit, No Report")** governance invariant:
1. **Unit Testing**: Validates target testbed database seeding, user authentication flow, route parameter extraction via AST analysis, SARIF 2.1.0 generation, and patch diff creation in isolation.
2. **Phase 1 Static AST Route & Risk Mapping Tests**: Validates that `RepoScanner` and `SurfaceMapper` correctly identify Python decorators (`@app.get`, `@router.post`), resolve `APIRouter(prefix="...")` prefixes, extract route parameters, and prioritize candidate targets.
3. **Phase 2-3 Dynamic Crawling & Live Exploitation Tests**: Validates that `DynamicCrawler`, `IdorExploitAgent`, `SqliExploitAgent`, and `MisconfigExploitAgent` execute non-destructive exploit probes against live endpoints.
4. **Phase 4 Proof-by-Exploitation & False Positive Suppression Tests**: Validates that `ProofValidator` confirms genuine breaches (HTTP 200 + leaked data payload) and suppresses theoretical candidates that fail dynamic validation.
5. **Phase 5 Reporting & Remediation Tests**: Validates that `SarifGenerator`, `MarkdownGenerator`, and `PatchGenerator` output compliant SARIF 2.1.0 schemas, markdown audit reports, and unified git diffs.
6. **End-to-End Pipeline & Defense Verification Tests**: Runs the full 5-phase autonomous pipeline against an active server and verifies that unpatched applications reveal proven breaches, while patched applications yield 0 false positives.

---

## 2. Test Execution Commands

```bash
# Run the complete automated test suite
.venv/bin/python3 -m unittest tests/test_hawkscan.py

# Launch both servers concurrently (ApexPortal port 8000 + HawkScan War Room port 9090)
.venv/bin/python3 launch.py

# Run HawkScan via CLI against target application and local repository
.venv/bin/python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -r target_app -o markdown
```

---

## 3. Verified Test Results (Ran 13 tests in 4.793s - 100% Passing)

| Test ID & Method | Focus Area | Result | Verified Runtime Output / Assertions | Verification Date |
| :--- | :--- | :--- | :--- | :--- |
| `test_01_target_app_db_and_auth` | Seeded DB & Authentication | **PASSED** | Seeded users `alice@apex.local` & `bob@apex.local`, confidential records `REC-9001` & `REC-9002`. Login sets `apex_session` cookie and Bearer token. | 2026-10-17 |
| `test_02_target_app_idor_vulnerability` | Unpatched BOLA / IDOR | **PASSED** | Alice accesses Bob's confidential record `REC-9001` ($42.5M M&A deal) across tenant boundaries. Returns HTTP 200 with `DATA_LEAK_CONFIRMED`. | 2026-10-17 |
| `test_03_target_app_sqli_vulnerability` | Unpatched SQL Injection | **PASSED** | Submitting boolean breakout `' OR '1'='1` to `/api/search?q=...` exfiltrates all tenant records. Returns HTTP 200 with >= 2 records. | 2026-10-17 |
| `test_04_target_app_patch_toggle` | Dynamic Security Toggles | **PASSED** | Toggling `/api/admin/toggle-patch?feature=idor&enabled=true` blocks Alice's cross-tenant access with HTTP 403 Forbidden while allowing her own record `REC-9002`. | 2026-10-17 |
| `test_05_static_analyzer_repo_scanner` | Phase 1 AST Route Scanner | **PASSED** | Analyzed `target_app`. Identified FastAPI framework, mapped routes `/api/records/{record_id}`, `/api/search`, `/api/auth/login`. Mapped attack surface. | 2026-10-17 |
| `test_06_proof_validator_no_exploit_no_report` | Phase 4 Proof Validator | **PASSED** | Proven breach with working PoC is retained (`HAWKSCAN-TEST-001`). Unproven candidate returning HTTP 403 is discarded as `DISCARDED_FALSE_POSITIVE`. | 2026-10-17 |
| `test_07_sarif_and_markdown_generator` | Phase 5 Artifact Generation | **PASSED** | Validates OASIS SARIF 2.1.0 schema with driver name "HawkScan", Markdown audit report with reproducible curl commands, and Git diff patches for `target_app/routes/records.py`. | 2026-10-17 |
| `test_08_hawkscan_server_api_and_ui` | HawkScan Control Plane API | **PASSED** | `GET /api/health` returns 200 OK with service "HawkScan AI Pentester Core". `GET /` serves HawkScan War Room UI. `POST /api/scan/start`, `GET /api/scan/report`, `GET /api/export/*` verified. | 2026-10-17 |
| `test_09_full_pipeline_end_to_end` | Phases 1-5 Live Execution | **PASSED** | Full autonomous pipeline executed against live background server. Verified 4 proven breaches (`HAWKSCAN-BOLA-001`, `HAWKSCAN-SQLI-001`, `HAWKSCAN-CORS-001`, `HAWKSCAN-COOKIE-001`). Includes step playback traces. | 2026-10-17 |
| `test_10_patch_toggle_prevents_false_positives` | "No Exploit, No Report" | **PASSED** | Patched target application results in 0 verified vulnerabilities reported and 1+ discarded false positives. Zero false alarms under active defense. | 2026-10-17 |
| `test_11_step_recorder` | Chronological Action Trace | **PASSED** | StepRecorder sequentially logs actions, numbering each step, capturing target, details, and outcome status badges. Generates GitHub Flavored Markdown table. | 2026-10-17 |
| `test_12_tinyfish_engine_loopback_and_lifecycle` | Dual-Engine Browser Automation | **PASSED** | TinyFishEngine detects loopback target, launches local headless Playwright Chromium, navigates, executes JS evaluation, extracts cookies, and tears down cleanly. | 2026-10-17 |
| `test_13_cookie_exploit_agent_breach` | Cookie Security & Session Theft | **PASSED** | CookieExploitAgent identifies missing HttpOnly attribute, executes `document.cookie` in DOM via TinyFish, steals session token, and proves replay against `/api/auth/me`. | 2026-10-17 |

---

## 4. Operational Invariants Verified

1. **Zero False Positives Under Defense**: When runtime security patches are active, theoretical static code risks (e.g. CORS origin reflection or raw SQL patterns that are mitigated) are filtered out during Phase 4 and not presented as vulnerabilities.
2. **Safe & Non-Destructive**: All probe payloads against `target_app` use non-destructive read operations (`GET` requests, syntax-valid boolean injections, and tenancy lookups), adhering strictly to Section 4 of `AGENTS.md`.
3. **Single-Command Launch & Clean Shutdown**: `launch.py` boots `target_app` on port 8000 and `hawkscan.server` on port 9090, listens for Ctrl+C, Ctrl+Q, or 'q', and cleanly terminates all sub-processes via process group signals.
