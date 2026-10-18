# ADR-0010: Target Website-First Omnibar and Optional Local Repository Architecture

## Status
Accepted

## Date
2026-10-18

## Authors
HawkScan Autonomous Pentester Core Team

## Context
Originally, HawkScan was launched with a dual-input omnibar requiring both a running target URL (`-u URL:`) and a local filesystem repository path (`-r REPO:`). In user workflows, demanding a local source repository path created unnecessary cognitive overhead, especially when security researchers or auditors wanted to perform penetration testing against live websites, staging domains, or microservice endpoints directly.

Furthermore, when testing without an explicit repo path, the scanner would either default to the entire parent project directory (introducing scanning noise) or error out.

## Decision
We redesigned HawkScan's UI and orchestration pipeline to be **Target Website-First**:

1. **War Room UI Omnibar Simplification (`hawkscan/server/static/index.html`)**:
   - Removed the `-r REPO:` input pill from the header omnibar entirely.
   - Introduced a dedicated, streamlined `🌐 TARGET WEBSITE:` input bar accepting web application targets (e.g. `http://127.0.0.1:8000` or `https://example.com`).
   - Integrated client-side protocol normalization: bare domain inputs (e.g. `getechodesk.in` or `127.0.0.1:8000`) automatically prefix `https://` or `http://`.
   - Updated pipeline step 1 label to `Attack Surface Recon`, metric pill to `🗺️ ATTACK SURFACE`, and pane tab to `🗺️ Target Attack Surface`.

2. **Backend Optionality & Intelligent Local Auto-Linking (`hawkscan/orchestrator/pipeline.py` & `hawkscan/server/app.py`)**:
   - `repo_path` is now completely optional across REST APIs (`POST /api/scan/start`), the `HawkScanPipeline` orchestrator, and the CLI (`hawkscan.cli start`).
   - If `repo_path` is omitted and the target URL resolves to the local development testbed (`127.0.0.1:8000` / `localhost:8000`), HawkScan automatically resolves `target_app/` if available on disk.
   - If targeting an external website or domain without a local repository, Phase 1 gracefully enters **Target Website Mode**, mapping the attack surface dynamically via the web prober.

3. **Dynamic Web Hyperlink Extraction (`hawkscan/dynamic_analyzer/crawler.py`)**:
   - Enhanced `DynamicCrawler` to inspect live HTML responses from the target website and extract hyperlinked internal routes (`href="/..."`), augmenting candidate attack routes without requiring static source code AST extraction.

4. **Reporting Cleanliness (`hawkscan/reporting/markdown_generator.py`)**:
   - Executive summaries and metadata tables omit the `Repository Analyzed` field when auditing in direct website mode, reporting clean assessment duration and proven breaches without irrelevant directory artifacts.

## Consequences

### Positive
- **Frictionless Onboarding**: Users simply enter a website URL and click **RUN PENTEST**.
- **Dual Support**: Full backwards compatibility is preserved for white-box CI/CD pipelines that explicitly pass `--repo / -r`.
- **Cleaner Telemetry**: Logs and reports reflect the actual website attack scope.

### Limitations
- In website-only mode against external third-party targets without OpenAPI specs, route discovery relies on dynamic web crawling and link discovery rather than AST code inspection.

## Alternatives Rejected
1. *Keep Local Repo Required*: Rejected due to user friction and inability to pentest arbitrary website endpoints without pointing to a directory.
2. *Separate Binary for Web vs Code*: Rejected to preserve HawkScan as a single unified autonomous pentester engine.
