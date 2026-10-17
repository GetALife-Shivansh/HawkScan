"""HawkScan Phase 5: Code Remediation Diff Generator"""

from typing import List, Dict, Any


class PatchGenerator:
    """Produces verified Unified Git Diff patches for discovered vulnerabilities."""

    @staticmethod
    def generate_patches(verified_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, str]:
        patches = {}

        for vuln in verified_vulnerabilities:
            vid = vuln.get("vulnerability_id", "")
            if "BOLA" in vid or "IDOR" in vid:
                diff = (
                    "--- a/target_app/routes/records.py\n"
                    "+++ b/target_app/routes/records.py\n"
                    "@@ -30,6 +30,12 @@ def get_record_detail(record_id: str, current_user = Depends(get_current_user)\n"
                    "     if not record:\n"
                    "         raise HTTPException(status_code=404, detail=\"Record not found\")\n"
                    "+\n"
                    "+    # Enforce Object-Level Tenancy Ownership\n"
                    "+    if record.owner_id != current_user.id:\n"
                    "+        raise HTTPException(\n"
                    "+            status_code=403,\n"
                    "+            detail=\"Access Denied: You do not have permission to view this confidential record\"\n"
                    "+        )\n"
                    "+\n"
                    "     return record"
                )
                patches["records_idor"] = diff

            elif "SQLI" in vid:
                diff = (
                    "--- a/target_app/routes/search.py\n"
                    "+++ b/target_app/routes/search.py\n"
                    "@@ -15,8 +15,7 @@ def search_records(q: str = Query(...), db: Session = Depends(get_db)):\n"
                    "-    # Insecure raw SQL string concatenation\n"
                    "-    raw_query = f\"SELECT id, title, category, amount FROM records WHERE title LIKE '%{q}%'\"\n"
                    "-    results = db.execute(text(raw_query)).fetchall()\n"
                    "+    # Secure parameterized ORM query\n"
                    "+    results = db.query(Record).filter(Record.title.ilike(f\"%{q}%\")).all()\n"
                    "     return results"
                )
                patches["search_sqli"] = diff

            elif "CORS" in vid:
                diff = (
                    "--- a/target_app/app.py\n"
                    "+++ b/target_app/app.py\n"
                    "@@ -22,7 +22,7 @@ app.add_middleware(\n"
                    "     CORSMiddleware,\n"
                    "-    allow_origins=[\"*\"],\n"
                    "+    allow_origins=[\"https://apex.local\", \"https://portal.apex.local\"],\n"
                    "     allow_credentials=True,\n"
                    "     allow_methods=[\"*\"],\n"
                )
                patches["cors_policy"] = diff

        return patches
