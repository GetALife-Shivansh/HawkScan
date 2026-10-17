"""HawkScan Control Plane Server & REST API
Exposes SSE real-time telemetry, pentest execution, report retrieval, and SARIF exports.
"""

import os
import signal
import asyncio
import json
import time
import httpx
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, BackgroundTasks, Request, Response, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hawkscan.config import settings
from hawkscan.orchestrator.pipeline import HawkScanPipeline

app = FastAPI(
    title="HawkScan Autonomous AI Penetration Testing Core",
    description="Proof-by-Exploitation AI Pentester for Web Applications & APIs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SSE Event stream subscriber queues
event_subscribers: List[asyncio.Queue] = []

current_dossier: Dict[str, Any] = {
    "status": "IDLE",
    "metadata": {
        "scan_id": None,
        "target_url": settings.DEFAULT_TARGET_URL,
        "repo_path": settings.DEFAULT_REPO_PATH,
        "duration_seconds": 0
    },
    "summary": {
        "verified_vulnerabilities": 0,
        "discarded_false_positives": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "live_endpoints_count": 0,
        "static_routes_count": 0
    },
    "verified_vulnerabilities": [],
    "discarded_false_positives": [],
    "attack_surface": {},
    "sarif": {},
    "markdown_report": "",
    "code_patches": {}
}


async def broadcast_event(stage: str, event_type: str, message: str, details: Dict[str, Any] = None):
    payload = {
        "timestamp": time.time(),
        "stage": stage,
        "event_type": event_type,
        "message": message,
        "details": details or {}
    }
    for q in event_subscribers:
        await q.put(payload)


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def get_ui():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "HawkScan AI Pentester Core",
        "version": "1.0.0",
        "default_target": settings.DEFAULT_TARGET_URL,
        "default_repo": settings.DEFAULT_REPO_PATH
    }


@app.get("/api/stream")
@app.get("/api/scan/stream")
async def sse_event_stream(request: Request):
    """Real-time SSE event stream delivering Phase 1-5 agent telemetry."""
    q = asyncio.Queue()
    event_subscribers.append(q)

    async def event_generator():
        try:
            yield f"data: {json.dumps({'message': 'Connected to HawkScan AI Pentester Telemetry Stream', 'stage': 'system', 'event_type': 'connected'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                event_data = await q.get()
                yield f"data: {json.dumps(event_data)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if q in event_subscribers:
                event_subscribers.remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    repo_path: Optional[str] = None


async def run_pipeline_task(target_url: str, repo_path: str):
    global current_dossier
    current_dossier["status"] = "RUNNING"
    current_dossier["metadata"]["target_url"] = target_url
    current_dossier["metadata"]["repo_path"] = repo_path

    pipeline = HawkScanPipeline(
        target_url=target_url,
        repo_path=repo_path,
        emit_callback=broadcast_event
    )

    try:
        dossier = await pipeline.run()
        current_dossier.update(dossier)
        current_dossier["status"] = "COMPLETED"
    except Exception as e:
        current_dossier["status"] = "ERROR"
        await broadcast_event("system", "error", f"HawkScan pipeline failed: {str(e)}")


@app.post("/api/scan/start")
async def start_scan(
    background_tasks: BackgroundTasks,
    request: Request
):
    """Triggers an autonomous white-box + dynamic penetration test."""
    t_url = None
    r_path = None
    try:
        body = await request.json()
        if isinstance(body, dict):
            t_url = body.get("target_url")
            r_path = body.get("repo_path")
    except Exception:
        pass

    target = (t_url or settings.DEFAULT_TARGET_URL).strip()
    repo = (r_path or settings.DEFAULT_REPO_PATH).strip()

    background_tasks.add_task(run_pipeline_task, target_url=target, repo_path=repo)

    return {
        "status": "started",
        "target_url": target,
        "repo_path": repo,
        "message": f"HawkScan AI Pentester launched against {target} with repo {repo}."
    }


@app.get("/api/scan/report")
def get_report():
    """Retrieves latest penetration testing dossier, verified PoCs, and SARIF output."""
    return current_dossier


@app.get("/api/export/sarif")
def export_sarif():
    """Downloads OASIS SARIF 2.1.0 output for CI/CD."""
    sarif = current_dossier.get("sarif", {})
    return Response(
        content=json.dumps(sarif, indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition": "attachment; filename=hawkscan-pentest-report.sarif"}
    )


@app.get("/api/export/markdown")
def export_markdown():
    """Downloads human-readable Markdown pentest report."""
    md = current_dossier.get("markdown_report", "# HawkScan Pentest Report\nNo results.")
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=hawkscan-pentest-report.md"}
    )


@app.post("/api/target/toggle-security")
async def toggle_target_security(
    target_url: str = Query("http://127.0.0.1:8000"),
    secure: bool = Query(False)
):
    """Sets target application to Insecure (vulnerable) or Secure (patched) mode."""
    endpoint = "/api/admin/make-secure" if secure else "/api/admin/make-insecure"
    full_url = f"{target_url.rstrip('/')}{endpoint}"
    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            r = await client.post(full_url)
            return r.json()
        except Exception as e:
            return {"status": "error", "message": f"Could not contact target at {full_url}: {e}"}


@app.get("/api/target/security-status")
async def get_target_security_status(target_url: str = Query("http://127.0.0.1:8000")):
    """Retrieves target application security posture."""
    full_url = f"{target_url.rstrip('/')}/api/admin/status"
    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            r = await client.get(full_url)
            return r.json()
        except Exception as e:
            return {"status": "unknown", "error": str(e)}


@app.post("/api/system/shutdown")
def shutdown_system():
    """Cleanly terminates HawkScan processes."""
    import threading
    def kill_soon():
        time.sleep(0.3)
        try:
            os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
        except Exception:
            os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=kill_soon, daemon=True).start()
    return {"status": "shutting_down", "message": "HawkScan services terminating cleanly."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hawkscan.server.app:app", host=settings.HAWKSCAN_HOST, port=settings.HAWKSCAN_PORT, reload=True)
