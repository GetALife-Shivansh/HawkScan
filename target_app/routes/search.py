"""Search Route (Target for SQL Injection exploitation)"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from target_app.database import SessionLocal, Record, SecurityConfig

router = APIRouter(prefix="/api/search", tags=["search"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("")
def search_records(
    q: str = Query(..., description="Search query string"),
    db: Session = Depends(get_db)
):
    """Searches corporate records by keyword.
    
    [HAWKSCAN SECURITY NOTE]:
    Vulnerable to SQL Injection (CWE-89 / OWASP A03:2021) via raw query
    concatenation when sqli_protection_enabled is False.
    """
    cfg = db.query(SecurityConfig).first()
    sqli_protected = cfg.sqli_protection_enabled if cfg else False

    if sqli_protected:
        # Secure parameterized ORM query
        results = db.query(Record).filter(
            (Record.title.ilike(f"%{q}%")) | (Record.category.ilike(f"%{q}%"))
        ).all()
        return [
            {"id": r.id, "title": r.title, "category": r.category, "amount": r.amount}
            for r in results
        ]

    # Insecure raw SQL string concatenation
    raw_query = f"SELECT id, title, category, amount FROM records WHERE title LIKE '%{q}%' OR category LIKE '%{q}%'"
    try:
        raw_result = db.execute(text(raw_query)).fetchall()
        return [
            {"id": row[0], "title": row[1], "category": row[2], "amount": row[3]}
            for row in raw_result
        ]
    except Exception as e:
        # SQL error disclosed to client, confirming injection vulnerability
        raise HTTPException(
            status_code=500,
            detail=f"Database execution error: {str(e)}"
        )
