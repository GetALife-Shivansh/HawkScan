"""HawkScan Control Plane Server & REST API
Exposes SSE real-time telemetry, pentest execution, report retrieval, and SARIF exports.
"""

import os
import signal
import asyncio
import json
import time
import httpx
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, BackgroundTasks, Request, Response, Query
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from hawkscan.config import settings
from hawkscan.orchestrator.pipeline import HawkScanPipeline
from hawkscan.engine.tinyfish_engine import TinyFishEngine

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


# =====================================================================
# TinyFish Autonomous Browser Control Plane Endpoints
# =====================================================================

global_browser_engine: Optional[TinyFishEngine] = None
global_browser_loop: Optional[asyncio.AbstractEventLoop] = None
global_browser_lock: Optional[asyncio.Lock] = None


def _is_loopback_url(url: Optional[str]) -> bool:
    if not url:
        return True
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local")
    except Exception:
        return False


async def get_or_create_browser(target_url: Optional[str] = None, force_engine: Optional[str] = None) -> TinyFishEngine:
    global global_browser_engine, global_browser_loop, global_browser_lock
    cur_loop = asyncio.get_running_loop()
    if global_browser_lock is None or global_browser_loop != cur_loop:
        global_browser_lock = asyncio.Lock()
        global_browser_engine = None
        global_browser_loop = cur_loop

    async with global_browser_lock:
        req_url = target_url or settings.DEFAULT_TARGET_URL
        is_loopback = _is_loopback_url(req_url)

        need_reinit = False
        if global_browser_engine is None or global_browser_engine.engine_mode == "CLOSED":
            need_reinit = True
        elif force_engine:
            if force_engine.upper() in ("CLOUD", "TINYFISH_CLOUD") and global_browser_engine.engine_mode != "TINYFISH_CLOUD":
                need_reinit = True
            elif force_engine.upper() in ("LOCAL", "LOCAL_PLAYWRIGHT") and global_browser_engine.engine_mode != "LOCAL_PLAYWRIGHT":
                need_reinit = True

        if need_reinit:
            if global_browser_engine and global_browser_engine.engine_mode != "CLOSED":
                try:
                    await global_browser_engine.close()
                except Exception:
                    pass
            global_browser_engine = TinyFishEngine(
                target_url=req_url,
                emit_fn=broadcast_event,
                verbose_terminal=True
            )
            force_c = (force_engine.upper() in ("CLOUD", "TINYFISH_CLOUD")) if force_engine else False
            force_l = (force_engine.upper() in ("LOCAL", "LOCAL_PLAYWRIGHT")) if force_engine else False
            # Default to TinyFish Cloud (with Cloudflare Tunnel for localhost targets)
            await global_browser_engine.start(force_cloud=force_c, force_local=force_l)
            if req_url:
                await global_browser_engine.navigate(req_url)
        elif target_url and global_browser_engine.target_url != target_url:
            await global_browser_engine.navigate(target_url)

        return global_browser_engine


@app.post("/api/browser/reconnect")
async def browser_reconnect(request: Request):
    """Explicitly switches or reconnects the browser engine (cloud, local, or auto)."""
    try:
        body = await request.json()
        target_url = body.get("url") or settings.DEFAULT_TARGET_URL
        mode = (body.get("mode") or "").strip().lower()  # "cloud", "local", or "auto"
        force_eng = mode if mode in ("cloud", "local") else None
        eng = await get_or_create_browser(target_url=target_url, force_engine=force_eng)
        state = await eng.get_state()
        await broadcast_event("browser", "reconnect", f"Switched engine to {state['engine_mode']} ({state['session_id']})", state)
        return {"status": "success", "state": state}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/browser/status")
async def get_browser_status(target_url: Optional[str] = None):
    """Retrieves active TinyFish autonomous browser telemetry, cookies, and screencast frame."""
    try:
        eng = await get_or_create_browser(target_url)
        state = await eng.get_state()
        return {"status": "success", "state": state}
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "state": {
                "engine_mode": "STANDBY",
                "session_id": "none",
                "target_url": target_url or settings.DEFAULT_TARGET_URL,
                "active_url": target_url or settings.DEFAULT_TARGET_URL,
                "last_action": "READY",
                "cookies": [],
                "cookies_count": 0,
                "screenshot_b64": None
            }
        }


@app.post("/api/browser/navigate")
async def browser_navigate(request: Request):
    """Commands TinyFish autonomous browser to navigate to a target URL."""
    try:
        body = await request.json()
        url = body.get("url", settings.DEFAULT_TARGET_URL).strip()
        eng = await get_or_create_browser(url)
        ok = await eng.navigate(url)
        await broadcast_event("browser", "navigate", f"TinyFish Browser navigated to {url}", {"url": url, "success": ok})
        state = await eng.get_state()
        return {"status": "success" if ok else "failed", "state": state}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.post("/api/browser/eval")
async def browser_eval_js(request: Request):
    """Executes JavaScript expression inside TinyFish live browser runtime."""
    try:
        body = await request.json()
        script = body.get("script", "document.cookie")
        eng = await get_or_create_browser()
        result = await eng.execute_js(script)
        await broadcast_event("browser", "eval_js", f"TinyFish executed JS: {script} -> {str(result)[:60]}", {"script": script, "result": result})
        state = await eng.get_state()
        return {"status": "success", "script": script, "result": result, "state": state}
    except Exception as e:
        return {"status": "error", "error": str(e)}


@app.get("/api/browser/cookies")
async def browser_get_cookies():
    """Retrieves cookies currently residing in the TinyFish browser context."""
    try:
        eng = await get_or_create_browser()
        cookies = await eng.get_cookies()
        return {"status": "success", "cookies": cookies, "count": len(cookies)}
    except Exception as e:
        return {"status": "error", "error": str(e), "cookies": [], "count": 0}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("hawkscan.server.app:app", host=settings.HAWKSCAN_HOST, port=settings.HAWKSCAN_PORT, reload=True)
