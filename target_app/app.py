"""Target Application Main Server (ApexPortal - Testbed for HawkScan)"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from target_app.database import init_db, SessionLocal, SecurityConfig
from target_app.routes.auth import router as auth_router
from target_app.routes.records import router as records_router
from target_app.routes.search import router as search_router
from target_app.routes.admin import router as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(force_insecure=True)
    yield


app = FastAPI(
    title="ApexPortal Corporate Cloud",
    description="Intentionally vulnerable enterprise testbed for HawkScan autonomous AI penetration testing",
    version="1.0.0",
    lifespan=lifespan
)


@app.middleware("http")
async def dynamic_cors_handler(request, call_next):
    """Dynamic CORS policy respecting runtime security patch state."""
    origin = request.headers.get("origin")
    response = await call_next(request)
    if origin:
        db = SessionLocal()
        cfg = db.query(SecurityConfig).first()
        cors_protected = cfg.cors_protection_enabled if cfg else False
        db.close()

        if cors_protected:
            # Defensive Mode: Only allow explicit trusted local origins
            if origin in ("http://127.0.0.1:8000", "http://127.0.0.1:9090", "http://localhost:8000", "http://localhost:9090"):
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
            else:
                if "access-control-allow-origin" in response.headers:
                    del response.headers["access-control-allow-origin"]
                if "access-control-allow-credentials" in response.headers:
                    del response.headers["access-control-allow-credentials"]
        else:
            # Insecure Mode: Reflect arbitrary untrusted origins with credentials enabled!
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "*"
    return response

# Mount Routes
app.include_router(auth_router)
app.include_router(records_router)
app.include_router(search_router)
app.include_router(admin_router)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def get_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "ApexPortal Enterprise Testbed", "port": 8000}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("target_app.app:app", host="127.0.0.1", port=8000, reload=True)
