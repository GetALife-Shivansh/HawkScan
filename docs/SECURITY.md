# Security Policy & Defensive Principles: HawkScan

## 1. Defensive Security Research Mission

HawkScan is built strictly for **defensive application security research**, developer auditing, pre-deployment security verification, and continuous regression detection.

HawkScan is intended to empower developers and security teams to identify reachable vulnerabilities before malicious actors can discover and exploit them. It must **never** be used against unauthorized third-party infrastructure without explicit written permission.

---

## 2. Safe & Non-Destructive Exploitation Invariants

In accordance with Section 4 of `AGENTS.md`, all exploit agents and dynamic probes in HawkScan must adhere to the following safety invariants:

1. **Non-Destructive Read Operations**:
   - All exploit probes directed by `IdorExploitAgent`, `SqliExploitAgent`, and `MisconfigExploitAgent` use non-destructive read operations (`GET` requests, read-only tenancy lookups, boolean syntax tests).
   - HawkScan never executes destructive SQL statements (`DROP`, `DELETE`, `UPDATE`, `INSERT`) or data-tampering payloads.
2. **Deterministic Syntax-Safe Payloads**:
   - SQL injection testing relies on syntax-valid boolean breakout payloads (`' OR '1'='1`) to observe result set expansion rather than out-of-band data corruption or blind time-delay denial of service.
3. **Controlled Scope & Boundary Enforcement**:
   - HawkScan only targets endpoints discovered within the target application's declared base URL and static attack surface.
   - External domains are rejected unless explicitly configured as mock test origins (e.g. `https://malicious-attacker.corp` for CORS origin reflection verification).
4. **Credential Isolation**:
   - All test credentials (`alice@apex.local`, `bob@apex.local`) and API keys are isolated to the local SQLite database and development `.env` environment.

---

## 3. Vulnerability Reporting & Responsible Disclosure

If you discover a security vulnerability or safety issue within HawkScan itself:
- Please report it privately to the maintainers rather than opening a public issue.
- Include a detailed description, reproduction steps, and any proof-of-concept payloads.
- The HawkScan team will acknowledge receipt within 24 hours and coordinate a timely patch.
