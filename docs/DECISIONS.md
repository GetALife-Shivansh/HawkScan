# Architecture Decision Records (ADR Index)

This document serves as the chronological index of architectural, design, and technical decisions for HawkScan.

| Identifier | Date | Title | Status | Implementation Status |
| :--- | :--- | :--- | :--- | :--- |
| [ADR-0001](decisions/0001-autonomous-whitebox-ai-pentester-architecture.md) | 2026-10-17 | HawkScan Autonomous White-Box AI Pentester Architecture | Accepted | Implemented |
| [ADR-0002](decisions/0002-proof-by-exploitation-doctrine.md) | 2026-10-17 | Proof-by-Exploitation ("No Exploit, No Report") Doctrine | Accepted | Implemented |
| [ADR-0003](decisions/0003-apexportal-vulnerable-testbed-and-dynamic-patches.md) | 2026-10-17 | ApexPortal Corporate Testbed & Dynamic Patch Architecture | Accepted | Implemented |
| [ADR-0004](decisions/0004-war-room-ui-and-sse-telemetry.md) | 2026-10-17 | War Room Web UI & Real-Time SSE Telemetry Stream | Accepted | Implemented |
| [ADR-0005](decisions/0005-oasis-sarif-and-remediation-patch-artifacts.md) | 2026-10-17 | OASIS SARIF 2.1.0 and Unified Remediation Patch Artifacts | Accepted | Implemented |
| [ADR-0006](decisions/0006-tinyfish-browser-agent-and-cookie-exploitation.md) | 2026-10-17 | TinyFish Browser Automation Engine & Cookie Security Exploitation | Accepted | Implemented |

---

### Decision Log Summary
1. **ADR-0001**: Established the 5-phase white-box pipeline uniting AST static code reconnaissance with dynamic multi-agent exploitation.
2. **ADR-0002**: Defined the "No Exploit, No Report" doctrine guaranteeing zero false positives when security defenses are active.
3. **ADR-0003**: Built the self-contained ApexPortal corporate testbed with togglable real-world IDOR and SQLi flaws.
4. **ADR-0004**: Designed the split-view cybersecurity War Room UI powered by server-sent telemetry events (SSE) on port 9090.
5. **ADR-0005**: Standardized machine-readable outputs into OASIS SARIF 2.1.0 schemas and unified git diff patches.
6. **ADR-0006**: Integrated TinyFish dual-engine browser automation, chronological StepRecorder, and CookieExploitAgent for DOM session theft verification.
