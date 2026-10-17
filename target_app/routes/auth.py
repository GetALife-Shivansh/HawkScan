"""Authentication routes for Target Application"""

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from target_app.database import SessionLocal, User, SecurityConfig

router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(req: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email, User.password == req.password).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    cfg = db.query(SecurityConfig).first()
    is_hardened = bool(cfg and getattr(cfg, "cookie_protection_enabled", False))

    # Issue session cookie: when not hardened, httponly=False (vulnerable to JS theft) and secure=False
    response.set_cookie(
        key="apex_session",
        value=user.token,
        httponly=True if is_hardened else False,
        secure=True if is_hardened else False,
        samesite="strict" if is_hardened else "lax"
    )
    return {
        "status": "success",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "token": user.token
        }
    }


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1].strip()
    elif "apex_session" in request.cookies:
        token = request.cookies["apex_session"]

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    user = db.query(User).filter(User.token == token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session or token")
    return user


@router.get("/me")
def get_current_user_profile(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role
    }
