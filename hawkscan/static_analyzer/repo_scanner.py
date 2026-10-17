"""HawkScan Phase 1: Static Repository Scanner & AST Route Extractor
Scans application source code locally to discover routes, framework patterns,
and potential attack vectors before dynamic interaction.
"""

import os
import re
import ast
from typing import List, Dict, Any, Optional, Callable


class RepoScanner:
    """Scans repository source code to map entry points, routes, and risk indicators."""

    def __init__(self, repo_path: str, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.repo_path = os.path.abspath(repo_path)
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("static_recon", msg)

    def scan_repository(self) -> Dict[str, Any]:
        """Performs static code reconnaissance across Python, JS, and config files."""
        self.log(f"Scanning local source repository at '{self.repo_path}'...")
        
        discovered_files = []
        routes = []
        risk_flags = []
        frameworks = set()

        if not os.path.exists(self.repo_path):
            self.log(f"Warning: Repository path '{self.repo_path}' not found on local disk.")
            return {
                "repo_path": self.repo_path,
                "frameworks": ["Unknown"],
                "routes": [],
                "risk_flags": [],
                "file_count": 0
            }

        # Walk repository files (excluding virtual environments and caches)
        for root, dirs, files in os.walk(self.repo_path):
            # Prune non-source directories
            dirs[:] = [d for d in dirs if d not in (".venv", "venv", "__pycache__", ".git", "node_modules", ".gemini")]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in (".py", ".js", ".ts", ".html", ".env", ".json"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.repo_path)
                    discovered_files.append(rel_path)

                    try:
                        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()

                        # Detect frameworks
                        if "fastapi" in content.lower():
                            frameworks.add("FastAPI (Python)")
                        if "flask" in content.lower():
                            frameworks.add("Flask (Python)")
                        if "express" in content.lower():
                            frameworks.add("Express.js (Node.js)")
                        if "sqlalchemy" in content.lower():
                            frameworks.add("SQLAlchemy ORM")

                        # Extract routes from Python files
                        if ext == ".py":
                            file_routes = self._extract_python_routes(content, rel_path)
                            routes.extend(file_routes)

                        # Code Risk Pattern Analysis
                        self._analyze_code_risks(content, rel_path, risk_flags)

                    except Exception as e:
                        self.log(f"Notice: Could not parse {rel_path}: {e}")

        framework_list = list(frameworks) if frameworks else ["Generic Web App"]
        self.log(f"Static scan complete. Analyzed {len(discovered_files)} files. Identified {len(routes)} routes and {len(risk_flags)} potential risk vectors across {', '.join(framework_list)}.")

        return {
            "repo_path": self.repo_path,
            "frameworks": framework_list,
            "routes": routes,
            "risk_flags": risk_flags,
            "file_count": len(discovered_files)
        }

    def _extract_python_routes(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Extracts route decorators e.g. @app.get('/api/...'), @router.post('...') using regex/AST."""
        routes = []
        
        # Check if the file defines an APIRouter or Blueprint with a prefix
        router_prefix = ""
        prefix_match = re.search(
            r'(?:APIRouter|Blueprint)\s*\([^)]*(?:prefix|url_prefix)\s*=\s*["\']([^"\']+)["\']',
            content,
            re.IGNORECASE
        )
        if not prefix_match:
            prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']+)["\']', content)
        if prefix_match:
            router_prefix = prefix_match.group(1).rstrip("/")

        # Pattern matching @(app|router).(get|post|put|delete|patch)("...")
        route_pattern = re.compile(
            r'@(app|router)\.(get|post|put|delete|patch)\(\s*["\']([^"\']*)["\']',
            re.IGNORECASE
        )
        for match in route_pattern.finditer(content):
            target_obj = match.group(1).lower()
            method = match.group(2).upper()
            raw_path = match.group(3)

            # Resolve full path considering router prefix
            if target_obj == "router" and router_prefix:
                if not raw_path or raw_path == "/":
                    path = router_prefix
                elif raw_path.startswith("/"):
                    path = router_prefix + raw_path
                else:
                    path = f"{router_prefix}/{raw_path}"
            else:
                path = raw_path if (raw_path.startswith("/") or not raw_path) else f"/{raw_path}"
                if not path:
                    path = "/"

            # Find function name following decorator
            fn_match = re.search(r'def\s+([a-zA-Z0-9_]+)\s*\(', content[match.end():])
            fn_name = fn_match.group(1) if fn_match else "handler"
            
            # Check if route takes parameterized ID
            params = re.findall(r'\{([a-zA-Z0-9_]+)\}', path)
            routes.append({
                "path": path,
                "method": method,
                "function": fn_name,
                "file": file_path,
                "parameters": params,
                "has_parameters": len(params) > 0
            })
        return routes

    def _analyze_code_risks(self, content: str, file_path: str, risk_flags: List[Dict[str, Any]]):
        """Identifies suspicious code patterns that warrant dynamic exploit testing."""
        # Check 1: Raw SQL string formatting (SQL Injection surface)
        if re.search(r'SELECT\s+.*(?:LIKE|WHERE)\s+.*(?:%s|f["\'].*\{|\.format\(|\+\s*[a-zA-Z0-9_]+)', content, re.IGNORECASE):
            risk_flags.append({
                "type": "SQL_INJECTION_SURFACE",
                "file": file_path,
                "severity": "HIGH",
                "description": "Raw SQL query string interpolation detected without parameterized binding.",
                "target_module": "sqli_agent"
            })

        # Check 2: Direct Object Reference parameter without ownership check
        if re.search(r'def\s+[a-zA-Z0-9_]+\(.*(?:id|record_id|appointment_id):.*db\.query\([A-Z][a-zA-Z]+\)\.filter\(', content):
            if "owner_id" not in content and "user_id" not in content and "patient_id" not in content:
                risk_flags.append({
                    "type": "IDOR_BOLA_CANDIDATE",
                    "file": file_path,
                    "severity": "CRITICAL",
                    "description": "Database object query keyed by user-supplied identifier without apparent ownership validation.",
                    "target_module": "idor_agent"
                })

        # Check 3: CORS wildcard with credentials enabled
        if 'allow_origins=["*"]' in content and 'allow_credentials=True' in content:
            risk_flags.append({
                "type": "CORS_WILDCARD_CREDENTIALS",
                "file": file_path,
                "severity": "CRITICAL",
                "description": "CORS middleware configured with wildcard allow_origins combined with allow_credentials.",
                "target_module": "misconfig_agent"
            })
