"""Admin & Security Configuration Route for Target Application"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from target_app.database import SessionLocal, SecurityConfig, init_db

router = APIRouter(prefix="/api/admin", tags=["admin"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/status")
def get_security_status(db: Session = Depends(get_db)):
    cfg = db.query(SecurityConfig).first()
    return {
        "idor_protection_enabled": cfg.idor_protection_enabled if cfg else False,
        "sqli_protection_enabled": cfg.sqli_protection_enabled if cfg else False,
        "cors_protection_enabled": cfg.cors_protection_enabled if cfg else False,
        "cookie_protection_enabled": getattr(cfg, "cookie_protection_enabled", False) if cfg else False
    }


@router.post("/toggle-patch")
def toggle_patch(
    feature: str = Query(..., description="Feature to toggle: 'idor', 'sqli', 'cors', or 'cookie'"),
    enabled: bool = Query(..., description="True to enable patch, False to disable"),
    db: Session = Depends(get_db)
):
    cfg = db.query(SecurityConfig).first()
    if not cfg:
        cfg = SecurityConfig(id=1)
        db.add(cfg)

    feat_lower = feature.lower().strip()
    if feat_lower == "idor":
        cfg.idor_protection_enabled = enabled
    elif feat_lower == "sqli":
        cfg.sqli_protection_enabled = enabled
    elif feat_lower == "cors":
        cfg.cors_protection_enabled = enabled
    elif feat_lower in ("cookie", "cookies"):
        cfg.cookie_protection_enabled = enabled
    else:
        raise HTTPException(status_code=400, detail="Unknown feature. Use 'idor', 'sqli', 'cors', or 'cookie'.")

    db.commit()
    return {
        "status": "success",
        "feature": feat_lower,
        "enabled": enabled,
        "idor_protection_enabled": cfg.idor_protection_enabled,
        "sqli_protection_enabled": cfg.sqli_protection_enabled,
        "cors_protection_enabled": cfg.cors_protection_enabled,
        "cookie_protection_enabled": getattr(cfg, "cookie_protection_enabled", False)
    }


@router.post("/make-insecure")
def make_insecure(db: Session = Depends(get_db)):
    """Disables all protections, exposing IDOR, SQLi, CORS, and Cookie vulnerabilities."""
    cfg = db.query(SecurityConfig).first()
    if not cfg:
        cfg = SecurityConfig(id=1)
        db.add(cfg)
    cfg.idor_protection_enabled = False
    cfg.sqli_protection_enabled = False
    cfg.cors_protection_enabled = False
    cfg.cookie_protection_enabled = False
    db.commit()
    return {
        "status": "success",
        "mode": "insecure",
        "message": "Target application is now INSECURE (IDOR, SQLi, CORS, and Cookie vulnerabilities active).",
        "idor_protection_enabled": False,
        "sqli_protection_enabled": False,
        "cors_protection_enabled": False,
        "cookie_protection_enabled": False
    }


@router.post("/make-secure")
def make_secure(db: Session = Depends(get_db)):
    """Enables all protections, mitigating IDOR, SQLi, CORS, and Cookie vulnerabilities."""
    cfg = db.query(SecurityConfig).first()
    if not cfg:
        cfg = SecurityConfig(id=1)
        db.add(cfg)
    cfg.idor_protection_enabled = True
    cfg.sqli_protection_enabled = True
    cfg.cors_protection_enabled = True
    cfg.cookie_protection_enabled = True
    db.commit()
    return {
        "status": "success",
        "mode": "secure",
        "message": "Target application is now HARDENED / PATCHED.",
        "idor_protection_enabled": True,
        "sqli_protection_enabled": True,
        "cors_protection_enabled": True,
        "cookie_protection_enabled": True
    }


@router.post("/reset-db")
def reset_database():
    init_db(force_insecure=True)
    return {"status": "success", "message": "Database reseeded to default vulnerable state."}
