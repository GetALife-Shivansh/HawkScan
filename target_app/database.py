"""Target Application Database Layer (Intentionally Vulnerable Testbed for HawkScan)
Pre-seeds users, multi-tenant financial records, and security configuration.
"""

import os
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, Float, text
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "target.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(120), unique=True, index=True)
    full_name = Column(String(120))
    role = Column(String(50), default="user") # 'admin' or 'user'
    token = Column(String(120), unique=True)
    password = Column(String(120))


class Record(Base):
    __tablename__ = "records"
    id = Column(String(50), primary_key=True, index=True)
    owner_id = Column(Integer, index=True) # User ID who owns this confidential record
    title = Column(String(200))
    category = Column(String(100)) # e.g. "Financial", "Legal", "M&A"
    confidential_data = Column(Text)
    amount = Column(Float, default=0.0)


class SecurityConfig(Base):
    __tablename__ = "security_config"
    id = Column(Integer, primary_key=True)
    idor_protection_enabled = Column(Boolean, default=False)
    sqli_protection_enabled = Column(Boolean, default=False)
    cors_protection_enabled = Column(Boolean, default=False)
    cookie_protection_enabled = Column(Boolean, default=False)

def init_db(force_insecure: bool = True):
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE security_config ADD COLUMN cookie_protection_enabled BOOLEAN DEFAULT 0"))
            conn.commit()
    except Exception:
        pass

    db = SessionLocal()

    # Seed or reset Security Configuration to vulnerable / insecure mode
    cfg = db.query(SecurityConfig).first()
    if not cfg:
        cfg = SecurityConfig(
            id=1,
            idor_protection_enabled=False,
            sqli_protection_enabled=False,
            cors_protection_enabled=False,
            cookie_protection_enabled=False
        )
        db.add(cfg)
        db.commit()
    elif force_insecure:
        cfg.idor_protection_enabled = False
        cfg.sqli_protection_enabled = False
        cfg.cors_protection_enabled = False
        cfg.cookie_protection_enabled = False
        db.commit()

    # Seed Users
    if not db.query(User).filter(User.email == "alice@apex.local").first():
        alice = User(
            id=1,
            email="alice@apex.local",
            full_name="Alice Johnson",
            role="user",
            token="apex_token_alice_sec_99182",
            password="password123"
        )
        db.add(alice)

    if not db.query(User).filter(User.email == "bob@apex.local").first():
        bob = User(
            id=2,
            email="bob@apex.local",
            full_name="Robert (Bob) Chen",
            role="user",
            token="apex_token_bob_sec_88412",
            password="password123"
        )
        db.add(bob)

    # Seed Confidential Multi-Tenant Records
    if not db.query(Record).filter(Record.id == "REC-9001").first():
        rec_bob = Record(
            id="REC-9001",
            owner_id=2, # Bob's confidential M&A financial record
            title="Q3 Strategic Acquisition & Valuation Portfolio",
            category="M&A Financial",
            confidential_data="CONFIDENTIAL: Proposed acquisition of FinTech Corp for $42,500,000 USD. Undisclosed wire transfer routing: US-FEDWIRE-9821049.",
            amount=42500000.0
        )
        db.add(rec_bob)

    if not db.query(Record).filter(Record.id == "REC-9002").first():
        rec_alice = Record(
            id="REC-9002",
            owner_id=1, # Alice's own record
            title="Vendor Services Contract - Cloud Infrastructure",
            category="Infrastructure",
            confidential_data="Routine vendor renewal for AWS Cloud Cluster compute instances. Total budget: $120,000 USD.",
            amount=120000.0
        )
        db.add(rec_alice)

    db.commit()
    db.close()
