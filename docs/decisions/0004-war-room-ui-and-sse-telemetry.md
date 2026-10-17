# ADR 0004: War Room Web UI & Real-Time SSE Telemetry Stream

## Status
Accepted

## Date
2026-10-17

## Context
Penetration testing audits often take several seconds or minutes to complete complex static scans, dynamic crawls, and concurrent exploit probes. Without real-time visibility into the agent's internal thoughts, HTTP requests, and phase transitions, security analysts and developers are left in the dark wondering if the scan is hanging or progressing.

Furthermore, viewing raw terminal output in a small console window makes it difficult to inspect complex JSON payloads, compare static attack surfaces with live endpoints, or examine confidential data leaks side-by-side with target webviews.

## Options Considered
1. **CLI-Only Output**:
   - *Pros*: Simple to maintain.
   - *Cons*: Limited visual fidelity; difficult to display concurrent multi-agent actions, attack surface hierarchies, and JSON evidence payloads simultaneously.
2. **Polling-Based REST UI**:
   - *Pros*: Standard HTTP request-response model.
   - *Cons*: High latency, unnecessary polling loops, and jerky UI updates.
3. **Split-Screen War Room UI with Server-Sent Events (SSE) (Selected)**:
   - *Pros*:
     - Unidirectional SSE stream (`GET /api/stream`) pushes instant, lightweight agent telemetry events directly to the browser with zero polling overhead.
     - Split-screen layout:
       - **Left Pane**: Dynamic tabs for Attack Surface hierarchy, live Target Webview iframe, and audit configuration inputs.
       - **Right Pane**: Real-time terminal log stream with stage badges (`STATIC_RECON`, `DYNAMIC_RECON`, `EXPLOITATION`, `VALIDATION`, `REPORTING`), alongside searchable verified findings, suppressed false positives, remediation patches, and export triggers.
     - Visual 5-Phase pipeline stepper ribbon with animated status indicators.
     - Built using Vanilla HTML5, CSS3, and JavaScript: zero Node.js build dependencies, zero Webpack/Vite complexity, fast rendering, and ultra-high reliability.

## Decision
Adopt Option 3. Implement `hawkscan/server/app.py` with FastAPI SSE endpoints and serve the frontend from `hawkscan/server/static/index.html` on port 9090.

## Consequences
- **Positive**:
  - Provides a cybersecurity war room experience with live telemetry and visual feedback.
  - Zero external npm/Node runtime dependencies required.
  - Accessible locally in any modern browser at `http://127.0.0.1:9090`.
- **Negative / Trade-offs**:
  - Requires maintaining vanilla JavaScript event listeners and DOM manipulation functions.

## Alternatives Rejected
- React/Vue SPA requiring separate node build toolchains: Rejected to preserve lightweight single-command Python deployment (`launch.py`).
