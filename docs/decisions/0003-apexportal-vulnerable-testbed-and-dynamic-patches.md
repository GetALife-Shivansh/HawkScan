# ADR 0003: ApexPortal Corporate Testbed & Dynamic Patch Architecture

## Status
Accepted

## Date
2026-10-17

## Context
To reliably test, evaluate, and benchmark HawkScan's multi-agent penetration testing capabilities, a realistic, self-contained target web application is required. Mocking HTTP requests in unit tests does not adequately test real socket connections, cookie headers, AST parameter extraction against real files, or the Proof Validator's dynamic suppression mechanics.

Furthermore, to verify that HawkScan does not produce false positives when security fixes are deployed, the testbed must support **runtime patch toggling** without restarting the process.

## Options Considered
1. **Mock Server Responses (Responses / WireMock)**:
   - *Pros*: Lightweight in-memory execution.
   - *Cons*: Fails to validate AST file scanning, SQLite ORM interaction, real HTTP connection pooling, or session state transitions.
2. **External Remote Vulnerable Apps (e.g. OWASP Juice Shop)**:
   - *Pros*: Industry standard.
   - *Cons*: Heavy dependencies (Node.js/Docker); lacks white-box Python AST compatibility; cannot dynamically toggle specific patches via lightweight API.
3. **ApexPortal Corporate Cloud Testbed (`target_app/`) (Selected)**:
   - *Pros*:
     - Full Python FastAPI + SQLite testbed running on port 8000.
     - Pre-seeded multi-tenant user accounts (`alice@apex.local`, `bob@apex.local`) and high-value confidential acquisition deals (`REC-9001` $42.5M portfolio, `REC-9002` $120k infrastructure contract).
     - Incorporates real-world vulnerability patterns:
       1. **Broken Object Level Authorization (BOLA/IDOR)** in `/api/records/{record_id}`.
       2. **SQL Injection (SQLi)** in `/api/search?q=...`.
       3. **Security Misconfiguration (CORS)** with wildcard origin reflection and credentials.
     - Provides dynamic patch administration API (`POST /api/admin/toggle-patch?feature=idor|sqli&enabled=true|false`), allowing instant switching between vulnerable and secure modes.

## Decision
Adopt Option 3. Implement `target_app/` as an enterprise cloud portal testbed. Concurrently launch `target_app` (port 8000) and `hawkscan` (port 9090) via `launch.py`.

## Consequences
- **Positive**:
  - Provides a predictable, reproducible environment for end-to-end integration tests (`tests/test_hawkscan.py`).
  - Allows immediate verification of both exploit generation (in insecure mode) and false positive suppression (in patched mode).
  - Works entirely offline with zero external network dependencies.
- **Negative / Trade-offs**:
  - Must ensure the database is reset to an insecure state during launches and tests to avoid test order dependence.

## Alternatives Rejected
- Third-party Docker container targets: Rejected to keep local installation dependencies minimal and allow native execution via the project's Python virtual environment.
