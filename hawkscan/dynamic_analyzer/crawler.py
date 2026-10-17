"""HawkScan Phase 2: Dynamic Reconnaissance & Live Target Crawler
Discovers active endpoints, establishes sessions, and maps live response headers.
"""

import httpx
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Optional, Callable


class DynamicCrawler:
    """Probes the live target web application to verify endpoints and obtain test sessions."""

    def __init__(self, target_url: str, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.target_url = target_url.rstrip("/")
        if not self.target_url.startswith(("http://", "https://")):
            self.target_url = f"https://{self.target_url}"
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("dynamic_recon", msg)

    async def crawl_and_authenticate(self, static_surface: Dict[str, Any]) -> Dict[str, Any]:
        """Runs dynamic verification, authenticates test user, and checks live endpoints."""
        self.log(f"Initiating dynamic exploration against running target at {self.target_url}...")

        live_endpoints = []
        auth_session = {
            "authenticated": False,
            "user_email": None,
            "token": None,
            "cookies": {}
        }
        server_headers = {}
        target_status_code = 0

        async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
            # Step 1: Base URL Health Check
            try:
                base_resp = await client.get(self.target_url, headers={"User-Agent": "HawkScan-AI-Pentester/1.0"})
                target_status_code = base_resp.status_code
                server_headers = dict(base_resp.headers)
                self.log(f"Target responded with HTTP {target_status_code} ({len(base_resp.content)} bytes).")
            except Exception as e:
                self.log(f"Warning: Failed to reach base URL {self.target_url}: {e}")

            # Step 2: Establish Legitimate Authenticated Session (Alice)
            login_url = urljoin(self.target_url, "/api/auth/login")
            try:
                login_resp = await client.post(
                    login_url,
                    json={"email": "alice@apex.local", "password": "password123"},
                    headers={"User-Agent": "HawkScan-AI-Pentester/1.0"}
                )
                if login_resp.status_code == 200:
                    data = login_resp.json()
                    user = data.get("user", {})
                    auth_session["authenticated"] = True
                    auth_session["user_email"] = user.get("email")
                    auth_session["token"] = user.get("token")
                    auth_session["cookies"] = dict(login_resp.cookies)
                    self.log(f"Authentication established for {auth_session['user_email']} (Token: {auth_session['token'][:16]}...).")
                else:
                    self.log(f"Auth endpoint returned HTTP {login_resp.status_code}. Proceeding with unauthenticated probes.")
            except Exception as e:
                self.log(f"Notice: Authentication attempt failed: {e}")

            # Step 3: Probe Discovered Routes from Static Analysis
            headers = {}
            if auth_session["token"]:
                headers["Authorization"] = f"Bearer {auth_session['token']}"

            candidate_paths = [
                "/api/health",
                "/api/records",
                "/api/records/REC-9002",
                "/api/search?q=test",
                "/api/admin/status",
                "/openapi.json",
                "/docs"
            ]

            # Merge with any static surface routes
            for r in static_surface.get("public_endpoints", []) + static_surface.get("authenticated_endpoints", []):
                p = r.get("path")
                if p and "{" not in p and p not in candidate_paths:
                    candidate_paths.append(p)

            for path in candidate_paths:
                full_url = urljoin(self.target_url, path)
                try:
                    resp = await client.get(
                        full_url,
                        headers=headers,
                        cookies=auth_session["cookies"],
                        timeout=3.5
                    )
                    live_endpoints.append({
                        "path": path,
                        "url": full_url,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "size_bytes": len(resp.content)
                    })
                except Exception:
                    pass

        self.log(f"Dynamic crawl complete. Verified {len(live_endpoints)} active endpoints on live target.")

        return {
            "target_url": self.target_url,
            "status_code": target_status_code,
            "server_headers": server_headers,
            "auth_session": auth_session,
            "live_endpoints": live_endpoints
        }
