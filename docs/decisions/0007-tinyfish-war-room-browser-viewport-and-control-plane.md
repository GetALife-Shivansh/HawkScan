# ADR-0007: TinyFish War Room Browser Viewport and Control Plane Integration

- **Status**: Accepted
- **Date**: 2026-10-17
- **Authors**: HawkScan Autonomous Pentester Core Team
- **Decision Category**: UI / Observability / Browser Control Plane

---

## 1. Context & Problem Statement

HawkScan's autonomous browser agent (`TinyFishEngine`) executes dynamic vulnerability probes, DOM inspection, cookie extraction, and session hijacking verifications against web targets. Previously, browser activity was communicated primarily through textual telemetry logs and final reports. 

Security researchers, developers, and auditors require first-class visual observability into the autonomous browser's live viewport, current URL, active session identifiers, live agent actions, cookie jar security attributes (HttpOnly, Secure, SameSite), and an interactive JavaScript DOM console to verify and reproduce client-side attack vectors in real time.

---

## 2. Options Considered

1. **Option A: Headless Logs Only**
   - Rely solely on stdout/stderr and SSE telemetry text feeds in the right pane.
   - *Drawback*: Lacks visual confirmation of DOM state, renders cookie inspection tedious, and provides no immediate visual feedback during multi-step browser exploitation.

2. **Option B: Standalone Electron / Desktop Window**
   - Launch a local desktop browser window or Electron wrapper on the host machine.
   - *Drawback*: Requires desktop GUI frameworks, fails in headless containerized CI/CD environments, and fragments the unified War Room interface.

3. **Option C: Native War Room Browser Window & Control Plane (Selected)**
   - Embed a primary `🐟 TinyFish Autonomous Browser` tab into the War Room UI (`http://127.0.0.1:9090`).
   - Implement complete browser window chrome: title bar with engine status tags (`LOCAL_PLAYWRIGHT` / `TINYFISH_CLOUD`), session ID chips, address bar with navigation controls, real-time Agent HUD banner, dual-mode viewport (interactive DOM iframe & engine base64 screencast), collapsible Cookie Jar inspector table, and live DOM JavaScript console.
   - Backed by asynchronous REST endpoints: `GET /api/browser/status`, `POST /api/browser/navigate`, `POST /api/browser/eval`, `GET /api/browser/cookies`.

---

## 3. Decision

We accept **Option C**:
1. **Left Workspace Pane**: Set `🐟 TinyFish Autonomous Browser` as the primary active tab in `hawkscan/server/static/index.html`.
2. **Dual-Mode Viewport**: Provide seamless switching between the live interactive DOM frame and the real-time Playwright/TinyFish base64 screencast snapshot.
3. **Agent HUD Banner**: Display a glowing cyan pulse banner at the top of the viewport streaming the active agent action in real time (`NAVIGATE`, `EVALUATE_JS`, `EXTRACT_COOKIES`).
4. **Interactive Cookie Jar & JS Console**: Offer a collapsible bottom drawer displaying parsed cookies with visual security badges (`HttpOnly`, `Secure`, `SameSite`, `XSS Stolen`), a live JavaScript evaluation terminal, and a dedicated `📜 Terminal Engine Logs` stream.
5. **Control Plane Endpoints**: Add `/api/browser/status`, `/api/browser/navigate`, `/api/browser/eval`, and `/api/browser/cookies` in `hawkscan/server/app.py`, ensuring dynamic event-loop safety for FastAPI and unit test runners.
6. **Live Terminal Logging**: Emit ANSI-colored `[TINYFISH]` logs with timestamps directly to OS terminal standard output (`sys.stdout`) with unbuffered streaming (`PYTHONUNBUFFERED=1`), while simultaneously broadcasting telemetry events to the War Room UI `TERMINAL & TELEMETRY STREAM` panel.

---

## 4. Consequences & Impact

### Positive:
- Immediate visual and interactive verification of browser state during automated pentests.
- One-click validation of cookie vulnerabilities (e.g., testing `document.cookie` DOM theft).
- Seamless operation across local loopback targets and remote TinyFish cloud sessions.
- Fully self-contained inside the existing single-page War Room app on port 9090.

### Negative / Trade-offs:
- Local Playwright browser context must be managed safely across asynchronous requests and test fixtures.
- Taking base64 JPEG screenshots on each action introduces minor CPU overhead (mitigated by setting 75% quality and viewport-only capture).

---

## 5. Alternatives Rejected

- **External Browser Popup**: Rejected because it requires window manager access, breaks in containerized/headless environments, and disconnects the browser from the War Room telemetry stream.
- **Polling Loop in Frontend**: Rejected in favor of reactive SSE integration (`initSSE` listens to `stage === 'browser'` and `stage === 'exploitation'`) combined with on-demand user navigation.
