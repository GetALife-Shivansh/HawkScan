# Operations Runbook: HawkScan

This document provides operational instructions for deploying, configuring, running, and troubleshooting HawkScan.

---

## 1. System Requirements & Prerequisites

- **Operating System**: macOS (Darwin), Linux, or Windows (WSL recommended).
- **Python Runtime**: Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Dependencies**: Listed in `requirements.txt` (FastAPI, Uvicorn, httpx, SQLAlchemy, Pydantic, python-dotenv).
- **Network Access**: Local loopback interface (`127.0.0.1`) for communication between HawkScan (port 9090) and target application (port 8000).

---

## 2. Environment Configuration

HawkScan loads settings from `.env` in the project root:

```ini
# HawkScan Control Plane
HAWKSCAN_HOST=127.0.0.1
HAWKSCAN_PORT=9090

# Target Application URL
TARGET_URL=http://127.0.0.1:8000

# Optional Multi-Provider LLM & Web Agent Keys
GEMINI_API_KEY=
TINYFISH_API_KEY=
TINYFISH_API_URL=https://api.browser.tinyfish.ai
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
DEFAULT_LLM_MODEL=gemini/gemini-3.5-flash

# Evidence Storage Directory
EVIDENCE_DIR=./evidence
```

---

## 3. Running HawkScan

### 3.1 Single-Command Monorepo Launcher (Recommended)

To start both the ApexPortal vulnerable testbed (port 8000) and the HawkScan War Room (port 9090), and automatically open the UI in your default browser:

```bash
.venv/bin/python3 launch.py
```

- **HawkScan War Room**: `http://127.0.0.1:9090`
- **Target Application**: `http://127.0.0.1:8000`
- **SARIF 2.1.0 Export**: `http://127.0.0.1:9090/api/export/sarif`
- **Markdown Export**: `http://127.0.0.1:9090/api/export/markdown`
- **SSE Stream**: `http://127.0.0.1:9090/api/stream`

To terminate all services cleanly, press `Ctrl+C`, `Ctrl+Q`, or type `q` in the terminal.

### 3.2 Standalone Command-Line Interface (CLI)

Run HawkScan directly against any target URL and repository path:

```bash
# Markdown audit report to stdout
.venv/bin/python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -r target_app -o markdown

# SARIF 2.1.0 output
.venv/bin/python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -r target_app -o sarif
```

### 3.3 Running the Automated Test Suite

```bash
.venv/bin/python3 -m unittest tests/test_hawkscan.py
```

---

## 4. Operational Workflows

### 4.1 Running a Penetration Test from the War Room UI
1. Open `http://127.0.0.1:9090` in your web browser.
2. In the top navigation bar, verify the **Target Application URL** (`http://127.0.0.1:8000`) and **Source Code Path** (`target_app`).
3. Click **"🚀 Launch Pentest"**.
4. Observe the **5-Phase Stepper** and **Real-Time SSE Telemetry Stream** as agents execute Phase 1 through 5.
5. Review verified vulnerabilities in the **"Verified Vulnerabilities"** tab, including working `curl` commands and exfiltrated payloads.
6. Review theoretical alerts that failed exploitation in the **"Suppressed False Positives"** tab.

### 4.2 Applying Remediation Patches
1. In the War Room UI, navigate to the **"Remediation Patches"** tab or fetch the dossier from `GET /api/scan/report`.
2. Copy the unified diff or save it to a patch file (e.g. `remediation.patch`).
3. Apply the patch to your source code:
   ```bash
   git apply remediation.patch
   ```

### 4.3 Verifying Zero False Positives Under Defense
1. In the War Room UI header, toggle the target application posture switch from **INSECURE** to **SECURE (DEFENDED)**.
2. Alternatively, invoke the API:
   ```bash
   curl -X POST "http://127.0.0.1:9090/api/target/toggle-security?secure=true"
   ```
3. Re-launch the pentest.
4. Verify that HawkScan reports **0 verified vulnerabilities** and classifies all theoretical code patterns as `DISCARDED_FALSE_POSITIVE`.

---

## 5. Troubleshooting & Maintenance

### Port Conflict (Port 8000 or 9090 already in use)
If port 8000 or 9090 is in use by another process:
```bash
lsof -i :8000
lsof -i :9090
kill -9 <PID>
```

### Resetting Target Database
To reset the ApexPortal database to its clean seeded state with insecure vulnerability modes enabled:
```bash
.venv/bin/python3 -c "from target_app.database import init_db; init_db(force_insecure=True)"
```
