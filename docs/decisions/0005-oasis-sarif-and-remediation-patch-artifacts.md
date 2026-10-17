# ADR 0005: OASIS SARIF 2.1.0 and Unified Remediation Patch Artifacts

## Status
Accepted

## Date
2026-10-17

## Context
A penetration test is only valuable if engineering and security operations can seamlessly consume its findings and fix the discovered vulnerabilities.
- Traditional security scanners often produce proprietary PDF or HTML reports that cannot be ingested into CI/CD pipelines (such as GitHub Code Scanning, GitLab Security Dashboard, or Jira automation).
- Furthermore, many scanners provide vague remediation advice (e.g., "Implement access control checks") without concrete, file-specific code patches, forcing developers to spend hours researching how to patch the vulnerability.

## Options Considered
1. **Plain Text / Custom JSON Only**:
   - *Pros*: Trivial to generate.
   - *Cons*: Cannot be ingested into GitHub Advanced Security or GitLab DAST out of the box; lacks standard schema validation.
2. **Standardized OASIS SARIF 2.1.0 + Unified Git Patches (Selected)**:
   - *Pros*:
     - **OASIS SARIF 2.1.0** (`SarifGenerator` in `hawkscan/reporting/sarif_generator.py`): The industry standard JSON schema for static and dynamic analysis. Enables native GitHub Security tab integration, automated PR annotations, and GitLab SAST/DAST ingestion.
     - **Executive Markdown Reports** (`MarkdownGenerator` in `hawkscan/reporting/markdown_generator.py`): Clean, executive-ready Markdown with copy-paste `curl` PoC commands, leaked payloads, and remediation guidance.
     - **Unified Git Diff Patches** (`PatchGenerator` in `hawkscan/reporting/patch_generator.py`): Generates unified diffs matching standard `git diff` format, allowing developers to review and apply security fixes directly via `git apply`.

## Decision
Adopt Option 2. Implement Phase 5 of the pipeline to produce SARIF 2.1.0, Markdown audit reports, and unified git diff patches, exposed via REST endpoints (`/api/export/sarif`, `/api/export/markdown`) and downloadable in the War Room UI.

## Consequences
- **Positive**:
  - Full interoperability with modern DevSecOps pipelines.
  - Accelerates mean-time-to-remediate (MTTR) by providing both verified reproduction steps and direct code patches.
  - Eliminates manual report translation into GitHub security alerts.
- **Negative / Trade-offs**:
  - Patch generation must accurately identify target file paths and line contexts from Phase 1 static analysis.

## Alternatives Rejected
- Binary PDF reports: Rejected due to heavy PDF library dependencies and lack of CI/CD machine-readability.
