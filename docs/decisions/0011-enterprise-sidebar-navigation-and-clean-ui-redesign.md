# ADR-0011: Enterprise Sidebar Navigation and Clean UI Redesign

## Status
Accepted

## Date
2026-10-18

## Authors
HawkScan Autonomous Pentester Core Team

## Context
Previously, the War Room UI presented all capabilities—the TinyFish browser window, target webview, static attack surface, telemetry feed, verified findings table, suppressed false positives, remediation patches, and SARIF exports—simultaneously within a dense two-column layout on a single viewport. Additionally, visual elements relied heavily on playful emojis, glowing neon borders, and flashy AI terminology, creating visual fatigue and a prototype-like aesthetic rather than an enterprise security product.

Users requested:
1. Make the UI clean, spacious, and simple.
2. Structure the interface with distinct sidebar navigation sections.
3. Eliminate the crowded single-screen clutter.
4. Remove all emojis from visible text and button elements.
5. Adopt a restrained, enterprise security aesthetic (similar to Snyk, Datadog, or GitHub Security) rather than a flashy AI prototype.

## Decision
We redesigned `hawkscan/server/static/index.html` to adopt an enterprise dark-mode sidebar navigation architecture:

1. **Fixed Left Navigation Sidebar**:
   - Clean 250px sidebar with high-contrast SVG stroke icons (no emojis).
   - Dedicated navigation sections:
     - **Dashboard**: High-level metrics (Breaches, Suppressed, Endpoints, Routes, Duration), scan progress stepper, and split overview.
     - **Vulnerabilities**: Dedicated full-width workspace with tabs for Verified Breaches and Suppressed False Positives, expandable proof-of-concept inspectors, and remediation advice.
     - **Attack Surface**: Tabular view of discovered routes, HTTP methods (`GET`, `POST`), parameters, and file mappings.
     - **TinyFish Autonomous Browser**: Full-width interactive browser viewport with screencast stream, HUD, cookie jar inspector, and DOM console.
     - **Audit Logs**: Dedicated full-width monospace terminal log stream with auto-scroll and clear actions.
     - **Reports & Patches**: One-click download cards for OASIS SARIF 2.1.0 JSON and Markdown, plus live Git diff patch inspectors.
   - Sidebar Footer: Displays live target posture (`INSECURE` / `PATCHED`), quick security toggle buttons, active browser engine status, and graceful service termination.

2. **Emoji Removal & Enterprise Design System**:
   - Replaced all emojis across headers, buttons, tabs, tables, and status badges with clean SVG line icons and precise typography.
   - Refined the color palette to standard enterprise dark-slate tokens (`#090d16` base, `#0d1322` sidebar, `#111827` cards, `#1f293d` borders) with muted text hierarchy (`#f8fafc`, `#94a3b8`, `#64748b`) and solid semantic indicators (Red for Critical, Green for Passed/Patched, Blue for Active).
   - Removed aggressive glowing drop-shadows and neon gradient animations.

3. **DOM ID and API Preservation**:
   - Preserved all IDs (`targetUrlInput`, `btnLaunch`, `statusBadge`, `mBreaches`, `mDiscarded`, `mLive`, `mStatic`, `mDuration`, `tfInteractiveFrame`, `tfHudBanner`, `tfBottomDrawer`, `tfCookieTableBody`, `tfPaneLogs`, `tfTabLogs`, `tfSwitchEngineBtn`, `tfTunnelChip`, `stage-tinyfish`), ensuring 100% compatibility with all test suites and control plane endpoints.

## Consequences

### Positive
- **Reduced Cognitive Load**: Users focus on one clear task at a time (Dashboard, Findings, Attack Surface, or Browser) without UI crowding.
- **Enterprise-Grade Presentation**: Professional appearance suitable for enterprise audits, SOC teams, and client demonstrations.
- **Zero Loss of Functionality**: Every automated pentest feature, SSE telemetry feed, and TinyFish CDP browser action operates identically.

### Limitations
- Multi-view layout requires sidebar clicks to switch between browser viewport and vulnerability details.

## Alternatives Rejected
1. *Keep Crowded Two-Column Layout*: Rejected due to user feedback regarding screen clutter and visual crowding.
2. *Collapsible Accordion Panels on Single Page*: Rejected as it still left the page cluttered and required constant scrolling.
