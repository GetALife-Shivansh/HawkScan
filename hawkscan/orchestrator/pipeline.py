"""HawkScan Orchestrator: 5-Phase Durable Penetration Testing Pipeline
Coordinates Static Code Analysis, Dynamic Crawling, Parallel Exploitation,
Proof-by-Exploitation Validation, and Artifact Generation.
"""

import asyncio
import time
import uuid
from typing import Dict, Any, List, Optional, Callable

from hawkscan.static_analyzer.repo_scanner import RepoScanner
from hawkscan.static_analyzer.surface_mapper import SurfaceMapper
from hawkscan.dynamic_analyzer.crawler import DynamicCrawler
from hawkscan.agents.idor_agent import IdorExploitAgent
from hawkscan.agents.sqli_agent import SqliExploitAgent
from hawkscan.agents.misconfig_agent import MisconfigExploitAgent
from hawkscan.agents.proof_validator import ProofValidator
from hawkscan.reporting.sarif_generator import SarifGenerator
from hawkscan.reporting.markdown_generator import MarkdownGenerator
from hawkscan.reporting.patch_generator import PatchGenerator


class HawkScanPipeline:
    """Orchestrates an autonomous white-box + dynamic penetration test."""

    def __init__(
        self,
        target_url: str,
        repo_path: str = ".",
        emit_callback: Optional[Callable[[str, str, str, Dict[str, Any]], Any]] = None
    ):
        self.target_url = target_url.strip()
        self.repo_path = repo_path.strip()
        self.emit_callback = emit_callback
        self.scan_id = f"hawkscan-{str(uuid.uuid4())[:8]}"

    async def emit(self, stage: str, event_type: str, message: str, details: Dict[str, Any] = None):
        if self.emit_callback:
            res = self.emit_callback(stage, event_type, message, details or {})
            if asyncio.iscoroutine(res):
                await res

    async def run(self) -> Dict[str, Any]:
        """Executes HawkScan's 5 phases in sequence."""
        start_time = time.time()
        await self.emit(
            "system",
            "pipeline_started",
            f"HawkScan Autonomous AI Pentester initialized. Target: {self.target_url} | Repo: {self.repo_path}",
            {"scan_id": self.scan_id, "target_url": self.target_url, "repo_path": self.repo_path}
        )

        def sync_emit(stage: str, msg: str):
            asyncio.create_task(self.emit(stage, "log", msg))

        # =================================================================
        # PHASE 1: Static Code Reconnaissance & AST Surface Mapping
        # =================================================================
        await self.emit("static_recon", "phase_started", "Phase 1: Starting static repository code analysis & route mapping...")
        scanner = RepoScanner(repo_path=self.repo_path, emit_fn=sync_emit)
        static_results = scanner.scan_repository()
        surface = SurfaceMapper.map_attack_surface(static_results)
        await self.emit(
            "static_recon",
            "phase_completed",
            f"Phase 1 Complete: Discovered {surface['total_routes']} routes and {surface['code_risk_count']} code risk patterns.",
            {"static_results": static_results, "surface": surface}
        )

        # =================================================================
        # PHASE 2: Dynamic Reconnaissance & Live Target Exploration
        # =================================================================
        await self.emit("dynamic_recon", "phase_started", f"Phase 2: Crawling running target at {self.target_url}...")
        crawler = DynamicCrawler(target_url=self.target_url, emit_fn=sync_emit)
        dynamic_results = await crawler.crawl_and_authenticate(surface)
        await self.emit(
            "dynamic_recon",
            "phase_completed",
            f"Phase 2 Complete: Verified {len(dynamic_results['live_endpoints'])} active endpoints. Auth state: {dynamic_results['auth_session']['authenticated']}.",
            {"dynamic_results": dynamic_results}
        )

        # =================================================================
        # PHASE 3: Vulnerability Analysis & Parallel Exploitation
        # =================================================================
        await self.emit("exploitation", "phase_started", "Phase 3: Launching parallel autonomous exploitation agents...")
        
        session = dynamic_results.get("auth_session", {})
        idor_agent = IdorExploitAgent(target_url=self.target_url, emit_fn=sync_emit)
        sqli_agent = SqliExploitAgent(target_url=self.target_url, emit_fn=sync_emit)
        misconfig_agent = MisconfigExploitAgent(target_url=self.target_url, emit_fn=sync_emit)

        # Execute live exploit agents concurrently
        idor_task = idor_agent.execute_exploit(session, surface)
        sqli_task = sqli_agent.execute_exploit(session, surface)
        misconfig_task = misconfig_agent.execute_exploit(session, surface)

        exploit_results = await asyncio.gather(idor_task, sqli_task, misconfig_task)
        await self.emit(
            "exploitation",
            "phase_completed",
            "Phase 3 Complete: All dynamic exploit attempts finished.",
            {"raw_exploit_count": sum(1 for e in exploit_results if e is not None)}
        )

        # =================================================================
        # PHASE 4: Proof-by-Exploitation Validation ("No Exploit, No Report")
        # =================================================================
        await self.emit("validation", "phase_started", "Phase 4: Evaluating proof-by-exploitation (suppressing false positives)...")
        validator = ProofValidator(emit_fn=sync_emit)
        verified_vulns, discarded_fps = validator.validate_and_filter(
            exploit_results=exploit_results,
            static_risk_flags=static_results.get("risk_flags", [])
        )
        await self.emit(
            "validation",
            "phase_completed",
            f"Phase 4 Complete: {len(verified_vulns)} proven breach(es) confirmed. {len(discarded_fps)} theoretical candidate(s) discarded.",
            {"verified_count": len(verified_vulns), "discarded_count": len(discarded_fps)}
        )

        # =================================================================
        # PHASE 5: Reporting & Artifact Generation
        # =================================================================
        await self.emit("reporting", "phase_started", "Phase 5: Generating SARIF 2.1.0, Markdown report, and Git remediation patches...")
        elapsed = round(time.time() - start_time, 2)
        
        metadata = {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "repo_path": self.repo_path,
            "duration_seconds": elapsed,
            "status": "COMPLETED"
        }

        sarif_data = SarifGenerator.generate_sarif(verified_vulns, self.target_url)
        markdown_report = MarkdownGenerator.generate_report(metadata, verified_vulns, discarded_fps)
        code_patches = PatchGenerator.generate_patches(verified_vulns)

        dossier = {
            "metadata": metadata,
            "summary": {
                "verified_vulnerabilities": len(verified_vulns),
                "discarded_false_positives": len(discarded_fps),
                "critical": sum(1 for v in verified_vulns if v.get("severity") == "CRITICAL"),
                "high": sum(1 for v in verified_vulns if v.get("severity") == "HIGH"),
                "medium": sum(1 for v in verified_vulns if v.get("severity") == "MEDIUM"),
                "low": sum(1 for v in verified_vulns if v.get("severity") == "LOW"),
                "live_endpoints_count": len(dynamic_results.get("live_endpoints", [])),
                "static_routes_count": len(static_results.get("routes", []))
            },
            "verified_vulnerabilities": verified_vulns,
            "discarded_false_positives": discarded_fps,
            "attack_surface": surface,
            "sarif": sarif_data,
            "markdown_report": markdown_report,
            "code_patches": code_patches
        }

        await self.emit(
            "system",
            "pipeline_completed",
            f"HawkScan Pentest Completed in {elapsed}s: {len(verified_vulns)} proven breach(es) found with working PoCs.",
            {"dossier": dossier}
        )

        return dossier


# Backwards compatibility alias
ShannonPipeline = HawkScanPipeline
