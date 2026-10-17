# ADR-0008: Dynamic Engine Arbitration, Loopback Safeguard, and TinyFish Cloud CDP Session Management

## Status
Accepted

## Context
When HawkScan boots or evaluates web applications, the TinyFish autonomous browser subsystem can run in either of two operational modes:
1. `LOCAL_PLAYWRIGHT`: Local headless/headed Chromium managed directly on the user's host machine.
2. `TINYFISH_CLOUD`: Remote cloud browser provisioned via TinyFish's cloud CDP API (`https://api.browser.tinyfish.ai`) over secure WebSockets (`wss://...`).

Users observed that when targeting the default local testbed (`http://127.0.0.1:8000`), the browser engine reports `Local Playwright Chromium active (Session: local-session-XXXX)` instead of a TinyFish Cloud session (`tf-XXXX`).

### The Architectural Problem: Loopback Reachability
TinyFish Cloud browsers execute inside remote Linux containers hosted in TinyFish cloud data centers (AWS US-West). If a cloud container attempts to navigate to `http://127.0.0.1:8000` or `http://localhost:8000`:
- The IP address `127.0.0.1` resolves to the *remote cloud container's own internal loopback interface*, not the user's local Mac workstation.
- Because nothing is listening on port 8000 inside that remote AWS container, requests fail immediately with `ECONNREFUSED` or socket timeout.
- Cloud browsers cannot access developer loopback environments without a reverse tunnel (e.g. ngrok or Cloudflare Tunnel).

Furthermore, previously, once a browser was initialized at server startup with `127.0.0.1:8000`, the server cached that engine instance indefinitely. When a user subsequently entered an external public website (e.g., `https://example.com` or `https://getechodesk.in`), the system continued to use the cached local instance rather than switching to TinyFish Cloud. Additionally, remote CDP sessions returned pre-existing contexts/pages that failed with `TargetClosedError` if `new_page()` was invoked redundantly.

## Decision
We implemented **Dynamic Engine Arbitration & Loopback Safeguarding**:

1. **Intelligent Loopback Safeguard**:
   - `TinyFishEngine._is_loopback(url)` inspects the hostname. For `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, and `.local`, HawkScan routes execution to `LOCAL_PLAYWRIGHT`.
   - The engine telemetry explicitly includes an `engine_reason` field clarifying why the session is local.

2. **Automated Cloud Escalation**:
   - For external/public domains (e.g., `https://example.com`), HawkScan automatically provisions a live `TINYFISH_CLOUD` CDP browser session via `https://api.browser.tinyfish.ai` using `TINYFISH_API_KEY`.
   - The engine detects existing remote contexts (`browser.contexts[0]`) and active pages (`context.pages[0]`), eliminating `TargetClosedError` during CDP connection.

3. **Runtime Engine Switching & Control Plane API**:
   - Implemented `POST /api/browser/reconnect` accepting `{"url": "...", "mode": "cloud" | "local" | "auto"}`.
   - When target address topology changes (local loopback vs. public cloud) or when user toggles the mode, HawkScan cleanly terminates the prior engine and launches the requested engine without restarting the server.

4. **War Room UI Engine Selector & Visual Telemetry**:
   - Added an interactive `[☁️ Switch to Cloud]` / `[💻 Switch to Local]` button to the TinyFish browser window toolbar in `index.html`.
   - The toolbar displays the active mode tag, engine reason tooltip, and live session identifier (`local-session-XXXX` vs `tf-XXXX`).

## Consequences

### Positive
- **Zero Configuration Friction**: Local testbeds work immediately out-of-the-box without network timeouts, while public targets leverage remote cloud CDP execution.
- **Explicit Transparency**: The user is never left wondering why a session is local or cloud—both the terminal logs and War Room HUD clearly state the rationale.
- **Manual Control**: Security auditors can force either mode on demand via the UI toolbar or REST endpoint.

### Limitations
- Local applications can only be audited via `TINYFISH_CLOUD` if exposed through a public tunnel (e.g. `ngrok http 8000`).

## Alternatives Rejected
1. *Attempting Cloud Connections to 127.0.0.1*: Rejected because cloud instances cannot resolve developer loopback, causing guaranteed connection failures.
2. *Requiring Manual Server Restarts to Switch Targets*: Rejected in favor of dynamic engine re-initialization inside `get_or_create_browser()`.
