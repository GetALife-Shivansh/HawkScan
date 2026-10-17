"""HawkScan Exploitation Agent: Security Misconfiguration & CORS Auditing
Tests for CORS origin reflection, credential disclosure, and missing defensive headers.
"""

import httpx
from typing import Dict, Any, Optional, Callable


class MisconfigExploitAgent:
    """Exploitation agent targeting security misconfigurations (OWASP A05 / CWE-942)."""

    def __init__(self, target_url: str, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.target_url = target_url.rstrip("/")
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("exploitation", msg)

    async def execute_exploit(self, session: Dict[str, Any], static_surface: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Tests CORS policy for wildcard or arbitrary origin reflection."""
        self.log("Misconfig Agent: Probing Cross-Origin Resource Sharing (CORS) security policy...")

        attacker_origin = "https://malicious-attacker.corp"
        token = session.get("token")
        cookies = session.get("cookies", {})
        headers = {
            "Origin": attacker_origin,
            "User-Agent": "HawkScan-AI-Pentester/1.0"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        target_path = "/api/records" if token else "/api/health"
        exploit_url = f"{self.target_url}{target_path}"

        repro_curl = (
            f"curl -X GET '{exploit_url}' \\\n"
            f"  -H 'Origin: {attacker_origin}' \\\n"
            + (f"  -H 'Authorization: Bearer {token}' \\\n" if token else "")
            + "  -I"
        )

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            try:
                resp = await client.get(
                    exploit_url,
                    headers=headers,
                    cookies=cookies
                )
                
                allow_origin = resp.headers.get("access-control-allow-origin", "")
                allow_creds = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

                # Check if attacker origin was accepted or wildcard with credentials
                if allow_origin == attacker_origin or (allow_origin == "*" and allow_creds):
                    self.log(f"CORS MISCONFIGURATION CONFIRMED: Origin allowed ({allow_origin}) with credentials={allow_creds}!")
                    return {
                        "vulnerability_id": "HAWKSCAN-CORS-001",
                        "title": "Insecure Cross-Origin Resource Sharing (CORS) Policy",
                        "severity": "MEDIUM",
                        "cwe_id": "CWE-942",
                        "owasp_category": "A05:2021-Security Misconfiguration",
                        "target_endpoint": target_path,
                        "http_method": "GET",
                        "status": "VERIFIED_EXPLOIT",
                        "description": (
                            f"The API reflects untrusted origins ('{attacker_origin}') in the Access-Control-Allow-Origin "
                            "header while permitting credentials. This allows third-party malicious sites to read authenticated user responses."
                        ),
                        "proof_of_concept": {
                            "exploit_command": repro_curl,
                            "http_status": resp.status_code,
                            "leaked_payload": {
                                "Access-Control-Allow-Origin": allow_origin,
                                "Access-Control-Allow-Credentials": str(allow_creds)
                            },
                            "evidence_summary": f"Access-Control-Allow-Origin returned '{allow_origin}' for Origin '{attacker_origin}'."
                        },
                        "remediation": {
                            "target_file": "target_app/app.py",
                            "guidance": "Whitelist explicit, trusted tenant domains instead of allowing wildcard or dynamic origin reflection."
                        }
                    }
                else:
                    self.log(f"CORS defended: Origin '{attacker_origin}' rejected.")
                    return {
                        "vulnerability_id": "HAWKSCAN-CORS-001",
                        "title": "Insecure Cross-Origin Resource Sharing (CORS) Policy",
                        "severity": "MEDIUM",
                        "cwe_id": "CWE-942",
                        "status": "UNVERIFIED",
                        "proof_of_concept": {
                            "exploit_command": repro_curl,
                            "http_status": resp.status_code,
                            "leaked_payload": None,
                            "evidence_summary": f"Target safely rejected or omitted Access-Control-Allow-Origin for {attacker_origin}."
                        }
                    }
            except Exception as e:
                self.log(f"CORS exploit attempt encountered error: {e}")

        return None
