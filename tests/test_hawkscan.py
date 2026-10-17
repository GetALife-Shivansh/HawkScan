"""Automated Test Suite for HawkScan: Autonomous White-Box AI Pentester
Validates all 5 phases:
- Phase 1: Static Code Reconnaissance & AST Route Mapping
- Phase 2: Dynamic Reconnaissance & Session Acquisition
- Phase 3: Vulnerability Analysis & Parallel Exploitation
- Phase 4: Proof-by-Exploitation Validation ("No Exploit, No Report")
- Phase 5: Reporting, SARIF 2.1.0 Export, and Code Remediation Diffs
"""

import os
import unittest
import asyncio
import threading
import time
import uvicorn
from fastapi.testclient import TestClient

from target_app.app import app as target_app
from target_app.database import init_db, SessionLocal, User, Record, SecurityConfig
from hawkscan.static_analyzer.repo_scanner import RepoScanner
from hawkscan.static_analyzer.surface_mapper import SurfaceMapper
from hawkscan.dynamic_analyzer.crawler import DynamicCrawler
from hawkscan.agents.idor_agent import IdorExploitAgent
from hawkscan.agents.sqli_agent import SqliExploitAgent
from hawkscan.agents.misconfig_agent import MisconfigExploitAgent
from hawkscan.agents.cookie_agent import CookieExploitAgent
from hawkscan.agents.proof_validator import ProofValidator
from hawkscan.engine import TinyFishEngine, StepRecorder
from hawkscan.reporting.sarif_generator import SarifGenerator
from hawkscan.reporting.markdown_generator import MarkdownGenerator
from hawkscan.reporting.patch_generator import PatchGenerator
from hawkscan.orchestrator.pipeline import HawkScanPipeline
from hawkscan.server.app import app as hawkscan_app


class TestHawkScanPentester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["HAWKSCAN_FORCE_LOCAL_TESTS"] = "1"
        init_db()
        cls.target_client = TestClient(target_app)
        cls.hawkscan_client = TestClient(hawkscan_app)
        cls.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        # Launch background uvicorn server for live end-to-end network tests
        cls.live_port = 8891
        cls.live_url = f"http://127.0.0.1:{cls.live_port}"
        cls.server_config = uvicorn.Config(target_app, host="127.0.0.1", port=cls.live_port, log_level="error")
        cls.server = uvicorn.Server(cls.server_config)
        cls.server_thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        # Reset database to insecure mode so tests never leave the target app patched
        db = SessionLocal()
        cfg = db.query(SecurityConfig).first()
        if cfg:
            cfg.idor_protection_enabled = False
            cfg.sqli_protection_enabled = False
            cfg.cors_protection_enabled = False
            cfg.cookie_protection_enabled = False
            db.commit()
        db.close()
        cls.server.should_exit = True
        cls.server_thread.join(timeout=2.0)

    def setUp(self):
        # Reset security config to vulnerable state before each test
        db = SessionLocal()
        cfg = db.query(SecurityConfig).first()
        if cfg:
            cfg.idor_protection_enabled = False
            cfg.sqli_protection_enabled = False
            cfg.cors_protection_enabled = False
            cfg.cookie_protection_enabled = False
            db.commit()
        db.close()

    def test_01_target_app_db_and_auth(self):
        """Verify seeded users, multi-tenant records, and authentication flow."""
        db = SessionLocal()
        users = db.query(User).all()
        emails = [u.email for u in users]
        self.assertIn("alice@apex.local", emails)
        self.assertIn("bob@apex.local", emails)

        records = db.query(Record).all()
        rec_ids = [r.id for r in records]
        self.assertIn("REC-9001", rec_ids)
        self.assertIn("REC-9002", rec_ids)
        db.close()

        # Test login
        resp = self.target_client.post("/api/auth/login", json={
            "email": "alice@apex.local",
            "password": "password123"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["user"]["full_name"], "Alice Johnson")
        self.assertIn("apex_session", resp.cookies)

    def test_02_target_app_idor_vulnerability(self):
        """Verify unpatched IDOR: Alice accesses Bob's confidential record REC-9001."""
        login_resp = self.target_client.post("/api/auth/login", json={
            "email": "alice@apex.local",
            "password": "password123"
        })
        alice_token = login_resp.json()["user"]["token"]

        # Request Bob's record (REC-9001) using Alice's Bearer token
        leak_resp = self.target_client.get(
            "/api/records/REC-9001",
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(leak_resp.status_code, 200)
        leak_data = leak_resp.json()
        self.assertEqual(leak_data["id"], "REC-9001")
        self.assertEqual(leak_data["owner_id"], 2) # Bob's ID
        self.assertIn("CONFIDENTIAL", leak_data["confidential_data"])
        self.assertEqual(leak_data["security_warning"], "DATA_LEAK_CONFIRMED")

    def test_03_target_app_sqli_vulnerability(self):
        """Verify unpatched SQLi: Boolean breakout payload dumps all records."""
        resp = self.target_client.get("/api/search?q=' OR '1'='1")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 2)
        rec_ids = [r["id"] for r in data]
        self.assertIn("REC-9001", rec_ids)
        self.assertIn("REC-9002", rec_ids)

    def test_04_target_app_patch_toggle(self):
        """Verify dynamic patch toggling blocks IDOR with HTTP 403."""
        # Enable IDOR patch
        patch_resp = self.target_client.post("/api/admin/toggle-patch?feature=idor&enabled=true")
        self.assertEqual(patch_resp.status_code, 200)
        self.assertTrue(patch_resp.json()["idor_protection_enabled"])

        # Login as Alice
        login_resp = self.target_client.post("/api/auth/login", json={
            "email": "alice@apex.local",
            "password": "password123"
        })
        alice_token = login_resp.json()["user"]["token"]

        # Re-probe Bob's record (REC-9001) -> Must return 403 Forbidden
        blocked_resp = self.target_client.get(
            "/api/records/REC-9001",
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(blocked_resp.status_code, 403)
        self.assertIn("Access Denied", blocked_resp.json()["detail"])

        # Alice's own record (REC-9002) must succeed
        own_resp = self.target_client.get(
            "/api/records/REC-9002",
            headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(own_resp.status_code, 200)
        self.assertEqual(own_resp.json()["id"], "REC-9002")

    def test_05_static_analyzer_repo_scanner(self):
        """Phase 1: Verify static code scanner extracts routes and risk patterns."""
        target_dir = os.path.join(self.repo_root, "target_app")
        scanner = RepoScanner(repo_path=target_dir)
        results = scanner.scan_repository()

        self.assertGreaterEqual(results["file_count"], 4)
        self.assertIn("FastAPI (Python)", results["frameworks"])

        route_paths = [r["path"] for r in results["routes"]]
        self.assertIn("/api/records/{record_id}", route_paths)
        self.assertIn("/api/search", route_paths)
        self.assertIn("/api/auth/login", route_paths)

        surface = SurfaceMapper.map_attack_surface(results)
        self.assertGreaterEqual(surface["total_routes"], 4)
        target_cats = [t["category"] for t in surface["prioritized_targets"]]
        self.assertIn("IDOR_BOLA", target_cats)
        self.assertIn("SQL_INJECTION", target_cats)

    def test_06_proof_validator_no_exploit_no_report(self):
        """Phase 4: Verify 'No Exploit, No Report' validator suppresses unverified warnings."""
        validator = ProofValidator()

        # 1. Verified Exploit (PoC achieved 200 OK and leaked data)
        valid_exploit = {
            "vulnerability_id": "HAWKSCAN-TEST-001",
            "title": "Broken Access Control",
            "severity": "CRITICAL",
            "cwe_id": "CWE-639",
            "proof_of_concept": {
                "exploit_command": "curl http://...",
                "http_status": 200,
                "leaked_payload": {"data": "secret"},
                "evidence_summary": "Extracted confidential data."
            }
        }

        # 2. Failed Exploit (Target returned 403 Forbidden - False Positive)
        failed_exploit = {
            "vulnerability_id": "HAWKSCAN-TEST-002",
            "title": "Blocked IDOR Candidate",
            "severity": "CRITICAL",
            "proof_of_concept": {
                "exploit_command": "curl http://...",
                "http_status": 403,
                "evidence_summary": "Access denied."
            }
        }

        static_flags = [{"type": "STATIC_WARNING", "file": "test.py"}]

        verified, discarded = validator.validate_and_filter([valid_exploit, failed_exploit], static_flags)

        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0]["vulnerability_id"], "HAWKSCAN-TEST-001")
        self.assertEqual(verified[0]["validation_status"], "PROVEN_BY_EXPLOITATION")

        self.assertGreaterEqual(len(discarded), 1)
        discarded_titles = [d["title"] for d in discarded]
        self.assertIn("Blocked IDOR Candidate", discarded_titles)

    def test_07_sarif_and_markdown_reporting(self):
        """Phase 5: Verify SARIF 2.1.0 schema compliance and Markdown generation."""
        verified_test_vulns = [
            {
                "vulnerability_id": "HAWKSCAN-BOLA-001",
                "title": "Broken Object Level Authorization (IDOR)",
                "severity": "CRITICAL",
                "cwe_id": "CWE-639",
                "owasp_category": "A01:2021-Broken Access Control",
                "target_endpoint": "/api/records/REC-9001",
                "http_method": "GET",
                "description": "Unauthorized record retrieval.",
                "proof_of_concept": {
                    "exploit_command": "curl http://...",
                    "http_status": 200,
                    "leaked_payload": {"id": "REC-9001"},
                    "evidence_summary": "Retrieved Bob's record."
                },
                "remediation": {
                    "target_file": "target_app/routes/records.py",
                    "guidance": "Enforce record.owner_id == user.id"
                }
            }
        ]

        # 1. SARIF 2.1.0 Generation
        sarif = SarifGenerator.generate_sarif(verified_test_vulns, "http://127.0.0.1:8000")
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "HawkScan")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["ruleId"], "HAWKSCAN-BOLA-001")
        self.assertEqual(run["results"][0]["level"], "error")

        # 2. Markdown Report Generation
        md = MarkdownGenerator.generate_report(
            {"target_url": "http://127.0.0.1:8000", "duration_seconds": 1.5},
            verified_test_vulns,
            []
        )
        self.assertIn("# 🦅 HawkScan Autonomous AI Penetration Testing Report", md)
        self.assertIn("HAWKSCAN-BOLA-001", md)
        self.assertIn("CWE-639", md)
        self.assertIn("curl http://...", md)

        # 3. Patch Diff Generation
        patches = PatchGenerator.generate_patches(verified_test_vulns)
        self.assertIn("records_idor", patches)
        self.assertIn("record.owner_id != current_user.id", patches["records_idor"])

    def test_08_hawkscan_server_api_and_ui(self):
        """Verify HawkScan REST API endpoints and War Room HTML."""
        # 1. GET /api/health
        health_resp = self.hawkscan_client.get("/api/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.json()["service"], "HawkScan AI Pentester Core")

        # 2. GET / (War Room UI)
        ui_resp = self.hawkscan_client.get("/")
        self.assertEqual(ui_resp.status_code, 200)
        self.assertIn("HAWKSCAN", ui_resp.text)
        self.assertIn("targetUrlInput", ui_resp.text)
        self.assertIn("repoPathInput", ui_resp.text)
        self.assertIn("Proof-by-Exploitation", ui_resp.text)

        # 3. POST /api/scan/start
        scan_resp = self.hawkscan_client.post("/api/scan/start", json={
            "target_url": "http://127.0.0.1:8000",
            "repo_path": "."
        })
        self.assertEqual(scan_resp.status_code, 200)
        self.assertEqual(scan_resp.json()["status"], "started")

        # 4. GET /api/scan/report
        report_resp = self.hawkscan_client.get("/api/scan/report")
        self.assertEqual(report_resp.status_code, 200)
        self.assertIn("summary", report_resp.json())

        # 5. GET /api/export/sarif
        sarif_resp = self.hawkscan_client.get("/api/export/sarif")
        self.assertEqual(sarif_resp.status_code, 200)

        # 6. GET /api/export/markdown
        md_resp = self.hawkscan_client.get("/api/export/markdown")
        self.assertEqual(md_resp.status_code, 200)

    def test_09_full_pipeline_end_to_end(self):
        """Phases 1-5: Full autonomous scan against live target application."""
        pipeline = HawkScanPipeline(
            target_url=self.live_url,
            repo_path=os.path.join(self.repo_root, "target_app")
        )
        dossier = asyncio.run(pipeline.run())
        self.assertEqual(dossier["metadata"]["status"], "COMPLETED")
        self.assertGreaterEqual(dossier["summary"]["verified_vulnerabilities"], 2)
        vuln_ids = [v["vulnerability_id"] for v in dossier["verified_vulnerabilities"]]
        self.assertIn("HAWKSCAN-BOLA-001", vuln_ids)
        self.assertIn("HAWKSCAN-SQLI-001", vuln_ids)
        self.assertIn("HAWKSCAN-COOKIE-001", vuln_ids)
        self.assertIn("sarif", dossier)
        self.assertIn("markdown_report", dossier)
        # Verify step-by-step playback table is present in Markdown report
        self.assertIn("Step-by-Step Exploit Playback Trace", dossier["markdown_report"])

    def test_10_patch_toggle_prevents_false_positives(self):
        """Phase 4 validation: patched application results in 0 verified vulnerabilities."""
        # Enable protections in DB
        db = SessionLocal()
        cfg = db.query(SecurityConfig).first()
        cfg.idor_protection_enabled = True
        cfg.sqli_protection_enabled = True
        cfg.cors_protection_enabled = True
        cfg.cookie_protection_enabled = True
        db.commit()
        db.close()

        pipeline = HawkScanPipeline(
            target_url=self.live_url,
            repo_path=os.path.join(self.repo_root, "target_app")
        )
        dossier = asyncio.run(pipeline.run())
        # With active defenses, zero exploits succeed -> zero false alarms reported!
        self.assertEqual(dossier["summary"]["verified_vulnerabilities"], 0)
        self.assertGreaterEqual(dossier["summary"]["discarded_false_positives"], 1)

    def test_11_step_recorder(self):
        """Verify StepRecorder maintains chronological action steps and markdown tables."""
        recorder = StepRecorder(agent_name="TestAgent")
        step1 = recorder.record_step("NAVIGATE", "http://127.0.0.1:8000", "Navigated to home", "SUCCESS")
        step2 = recorder.record_step("INJECT_PAYLOAD", "/api/search", "Submitted payload", "BREACH_CONFIRMED")
        self.assertEqual(step1["step"], 1)
        self.assertEqual(step2["step"], 2)
        steps = recorder.get_steps()
        self.assertEqual(len(steps), 2)
        table = recorder.to_markdown_table()
        self.assertIn("| Step | Action |", table)
        self.assertIn("NAVIGATE", table)
        self.assertIn("INJECT_PAYLOAD", table)

    def test_12_tinyfish_engine_loopback_and_lifecycle(self):
        """Verify TinyFishEngine automatically handles loopback target and executes browser tasks."""
        async def run_browser_test():
            engine = TinyFishEngine(target_url=self.live_url)
            self.assertTrue(engine._is_loopback(self.live_url))
            mode = await engine.start(force_local=True)
            self.assertEqual(mode, "LOCAL_PLAYWRIGHT")
            ok = await engine.navigate(self.live_url)
            self.assertTrue(ok)
            js_res = await engine.execute_js("10 + 20")
            self.assertEqual(js_res, 30)
            await engine.close()

            # Test tunnel manager utility
            from hawkscan.engine.tunnel_manager import tunnel_manager
            bin_path = tunnel_manager.find_cloudflared_binary()
            self.assertTrue(bin_path is not None and "cloudflared" in bin_path)

        asyncio.run(run_browser_test())

    def test_13_cookie_exploit_agent_breach(self):
        """Verify CookieExploitAgent identifies missing HttpOnly and confirms client-side theft."""
        async def run_cookie_test():
            agent = CookieExploitAgent(target_url=self.live_url)
            result = await agent.execute_exploit(session={}, static_surface={})
            self.assertIsNotNone(result)
            self.assertEqual(result["vulnerability_id"], "HAWKSCAN-COOKIE-001")
            self.assertEqual(result["severity"], "HIGH")
            self.assertIn("cookie_audit", result)
            self.assertFalse(result["cookie_audit"]["http_only"])
            self.assertTrue(result["cookie_audit"]["accessible_via_js"])
            self.assertIn("recorded_steps", result)
            self.assertGreaterEqual(len(result["recorded_steps"]), 3)

        asyncio.run(run_cookie_test())

    def test_14_browser_control_plane_and_ui_endpoints(self):
        """Verify War Room UI exposes TinyFish browser and /api/browser control plane functions."""
        # 1. Test UI index.html includes TinyFish Autonomous Browser components
        ui_resp = self.hawkscan_client.get("/")
        self.assertEqual(ui_resp.status_code, 200)
        self.assertIn("🐟 TinyFish Autonomous Browser", ui_resp.text)
        self.assertIn("tfInteractiveFrame", ui_resp.text)
        self.assertIn("tfHudBanner", ui_resp.text)
        self.assertIn("tfBottomDrawer", ui_resp.text)
        self.assertIn("tfCookieTableBody", ui_resp.text)
        self.assertIn("tfPaneLogs", ui_resp.text)
        self.assertIn("tfTabLogs", ui_resp.text)
        self.assertIn("tfSwitchEngineBtn", ui_resp.text)
        self.assertIn("tfTunnelChip", ui_resp.text)
        self.assertIn("stage-tinyfish", ui_resp.text)

        # 2. Test /api/browser/status endpoint
        status_resp = self.hawkscan_client.get(f"/api/browser/status?target_url={self.live_url}")
        self.assertEqual(status_resp.status_code, 200)
        status_data = status_resp.json()
        self.assertEqual(status_data["status"], "success")
        self.assertIn("engine_mode", status_data["state"])
        self.assertIn("session_id", status_data["state"])
        self.assertIn("engine_reason", status_data["state"])
        self.assertIn("tunnel_url", status_data["state"])

        # 3. Test /api/browser/reconnect endpoint
        reconnect_resp = self.hawkscan_client.post("/api/browser/reconnect", json={"url": self.live_url, "mode": "local"})
        self.assertEqual(reconnect_resp.status_code, 200)
        rec_data = reconnect_resp.json()
        self.assertEqual(rec_data["status"], "success")
        self.assertEqual(rec_data["state"]["engine_mode"], "LOCAL_PLAYWRIGHT")

        # 4. Test /api/browser/navigate endpoint
        nav_resp = self.hawkscan_client.post("/api/browser/navigate", json={"url": self.live_url})
        self.assertEqual(nav_resp.status_code, 200)
        nav_data = nav_resp.json()
        self.assertEqual(nav_data["status"], "success")

        # 5. Test /api/browser/eval endpoint
        eval_resp = self.hawkscan_client.post("/api/browser/eval", json={"script": "100 * 2"})
        self.assertEqual(eval_resp.status_code, 200)
        eval_data = eval_resp.json()
        self.assertEqual(eval_data["status"], "success")
        self.assertEqual(eval_data["result"], 200)

        # 6. Test /api/browser/cookies endpoint
        cookie_resp = self.hawkscan_client.get("/api/browser/cookies")
        self.assertEqual(cookie_resp.status_code, 200)
        cookie_data = cookie_resp.json()
        self.assertEqual(cookie_data["status"], "success")
        self.assertIsInstance(cookie_data["cookies"], list)

        # 6. Test TinyFishEngine terminal logger and telemetry emitter
        emitted_logs = []
        engine = TinyFishEngine(
            target_url=self.live_url,
            emit_fn=lambda s, ev, msg, det: emitted_logs.append((s, msg)),
            verbose_terminal=True
        )
        engine._log("Test TinyFish terminal stream message", level="INFO")
        self.assertGreaterEqual(len(emitted_logs), 1)
        self.assertEqual(emitted_logs[0][0], "tinyfish")
        self.assertIn("Test TinyFish terminal stream message", emitted_logs[0][1])

    def test_15_cloudflare_tunnel_and_tinyfish_cloud_mode(self):
        """Verify CloudflareTunnelManager URL mapping and TinyFish Cloud default mode configuration."""
        from hawkscan.engine.tunnel_manager import CloudflareTunnelManager, tunnel_manager

        # 1. Binary discovery
        bin_path = tunnel_manager.find_cloudflared_binary()
        self.assertTrue(bin_path is not None)

        # 2. URL translation logic
        mgr = CloudflareTunnelManager()
        mgr.public_url = "https://mock-hawkscan-tunnel.trycloudflare.com"
        mgr.local_target_url = "http://127.0.0.1:8000"

        # Local to tunnel translation
        mapped = mgr.map_local_to_tunnel("http://127.0.0.1:8000/api/records/REC-9001?flag=true")
        self.assertEqual(mapped, "https://mock-hawkscan-tunnel.trycloudflare.com/api/records/REC-9001?flag=true")

        # Tunnel to local translation
        reversed_url = mgr.map_tunnel_to_local("https://mock-hawkscan-tunnel.trycloudflare.com/api/search")
        self.assertEqual(reversed_url, "http://127.0.0.1:8000/api/search")

        # External URLs remain untouched
        external = mgr.map_local_to_tunnel("https://example.com/login")
        self.assertEqual(external, "https://example.com/login")

        # 3. TinyFishEngine state reporting tunnel_url
        engine = TinyFishEngine(target_url="http://127.0.0.1:8000")
        engine.engine_mode = "TINYFISH_CLOUD"
        engine.session_id = "tf-mock-session"
        engine.tunnel_url = "https://mock-hawkscan-tunnel.trycloudflare.com"

        async def verify_state():
            state = await engine.get_state()
            self.assertEqual(state["engine_mode"], "TINYFISH_CLOUD")
            self.assertEqual(state["tunnel_url"], "https://mock-hawkscan-tunnel.trycloudflare.com")
            self.assertIn("Cloudflare Tunnel", state["engine_reason"])

        asyncio.run(verify_state())


if __name__ == "__main__":
    unittest.main()

