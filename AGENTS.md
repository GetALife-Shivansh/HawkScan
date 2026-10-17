# Engineering Instructions & Governance (AGENTS.md)

This repository follows strict engineering governance. Every autonomous agent or human contributor working on this codebase must adhere to the following rules:

## 1. Governance & Documentation Invariants
- Maintain both the working software and an accurate, continuously updated record of its design, decisions, implementation, tests, and limitations.
- All documentation must reflect the **actual** repository and **actual** runtime behavior. Never invent completed work, mock outputs, or test results.
- When an attribute or metric is unverified or unknown, label it explicitly as `Unknown` or `Not yet verified`.
- Every meaningful feature or architectural change must update affected docs in `docs/` in the same session.

## 2. Decision Record Requirement
- Significant technical decisions must be recorded in `docs/decisions/` as an Architecture Decision Record (ADR) using the standard format (Status, Context, Options, Decision, Consequences, Alternatives Rejected).
- Keep `docs/DECISIONS.md` synchronized as a chronological index.

## 3. Testing and Definition of Done
- No task is complete until automated checks or smoke tests have been executed and their actual outputs recorded in `docs/TESTING.md`.
- Distinguish between tests written, tests executed, and tests passed.
- Report progress at the end of each task according to the 7-point progress reporting protocol.

## 4. Security & Safety Principles
- HawkScan is built strictly for defensive application security research, developer auditing, and continuous regression detection.
- All validation probes against target applications must be safe and non-destructive (e.g. read-only checks, header verification, no destructive payloads, no data tampering).
