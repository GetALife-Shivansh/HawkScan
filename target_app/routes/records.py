"""Confidential Records Route (Target for IDOR / BOLA exploitation)"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from target_app.database import SessionLocal, Record, SecurityConfig, User
from target_app.routes.auth import get_current_user

router = APIRouter(prefix="/api/records", tags=["records"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("")
def list_records(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Returns accessible records for the current user."""
    records = db.query(Record).filter(Record.owner_id == current_user.id).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "category": r.category,
            "amount": r.amount
        }
        for r in records
    ]


@router.get("/{record_id}")
def get_record_detail(
    record_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve details for a specific confidential record.
    
    [HAWKSCAN SECURITY NOTE]:
    Vulnerable to Broken Object Level Authorization (IDOR / CWE-639 / OWASP API1:2023)
    when idor_protection_enabled is False.
    """
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    cfg = db.query(SecurityConfig).first()
    idor_protected = cfg.idor_protection_enabled if cfg else False

    # Enforce Tenant Ownership (When Patch is Enabled)
    if idor_protected:
        if record.owner_id != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="Access Denied: You do not have permission to view this confidential record"
            )

    # Return record payload (Leaking cross-tenant data if unprotected)
    return {
        "id": record.id,
        "owner_id": record.owner_id,
        "title": record.title,
        "category": record.category,
        "confidential_data": record.confidential_data,
        "amount": record.amount,
        "security_warning": "DATA_LEAK_CONFIRMED" if (record.owner_id != current_user.id) else "AUTHORIZED_ACCESS"
    }
