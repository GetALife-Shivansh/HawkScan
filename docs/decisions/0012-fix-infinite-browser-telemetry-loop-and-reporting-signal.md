# ADR-0012: Fix Infinite Browser Telemetry Loop and Report Generation Signal

## 1. Status
**Accepted** (2026-10-18)

---

## 2. Context
During autonomous pentest execution, after `CookieExploitAgent` confirmed session cookie theft and terminated its session, the terminal and War Room UI became trapped in an infinite loop:
```text
[19:12:28] [TINYFISH] Captured live viewport screencast (33.4 KB)
[19:12:28] [TINYFISH] Navigated to http://127.0.0.1:8000
[19:12:29] [TINYFISH] Inspected cookie jar: 0 cookie(s) found []
[19:12:29] [TINYFISH] Inspected cookie jar: 0 cookie(s) found []
... (repeated 10-20 times per second indefinitely)
```
Simultaneously, the frontend never transitioned to `COMPLETED`, remaining stuck on step 4 and failing to display the final report and findings dossier.

---

## 3. Root Cause Analysis
Two interconnected issues caused this failure:
1. **Telemetry Positive Feedback Loop**:
   - In `TinyFishEngine.get_cookies()`, every read invoked `self._log(f"Inspected cookie jar: ...")`.
   - `self._log()` dispatched an SSE event to the client with `stage: "tinyfish"`.
   - In `index.html`, any SSE event with `stage === 'browser' || stage === 'tinyfish'` immediately triggered `fetchBrowserStatus()`.
   - `GET /api/browser/status` invoked `eng.get_state()`, which invoked `eng.get_cookies()`.
   - `get_cookies()` logged again, emitting another SSE event.
   - This produced a runaway self-sustaining loop hammering `/api/browser/status` dozens of times per second, overwhelming the server event loop.
2. **Missing Phase 5 Completion Event in Pipeline**:
   - `HawkScanPipeline` in `pipeline.py` generated SARIF, markdown reports, and patches, but only emitted `stage: "system", event_type: "pipeline_completed"`.
   - It failed to emit `stage: "reporting", event_type: "phase_completed"`.
   - The UI was solely listening for `d.stage === 'reporting' && d.event_type === 'phase_completed'` to trigger `loadLatestReport()` and set status to `COMPLETED`.

---

## 4. Options Considered
1. **Option A: Client-side polling only**
   - Disconnect the live HUD from browser events and poll `/api/browser/status` on a slow 5-second timer.
   - *Drawback*: Degrades real-time responsiveness of the live browser HUD during exploitation.
2. **Option B: Quiet Getter Pattern + Client-side Debounce + Dual-Event Completion (Selected)**
   - Remove `self._log` from passive reader/getter methods (`get_cookies`, `_capture_latest_screenshot`). Only log intentional, active agent actions.
   - Introduce `debouncedFetchBrowserStatus()` in the UI with a 1500ms cooldown window.
   - Emit `reporting / phase_completed` in `pipeline.py` and listen for both `phase_completed` and `pipeline_completed` in the UI.
   - Add a 2500ms safety-net polling interval in the frontend that checks `/api/scan/report` while scan status is running.

---

## 5. Decision
- Suppress passive logging inside `TinyFishEngine` state inspection methods (`get_cookies`, `_capture_latest_screenshot`).
- Implement debounced status fetching in `hawkscan/server/static/index.html`.
- Properly emit `reporting / phase_completed` in `HawkScanPipeline`.
- Add safety net polling on `/api/scan/report` when `currentScanState === 'running'`.

---

## 6. Consequences & Invariants
- Zero telemetry feedback loops; polling `/api/browser/status` produces 0 terminal log lines and 0 SSE echoes.
- Pentest runs cleanly complete Phase 5, automatically transition the War Room to `COMPLETED`, mark all 5 progress steps completed, and render the findings dossier, metrics, patches, and SARIF exports.
