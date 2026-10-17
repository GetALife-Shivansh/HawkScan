"""HawkScan Phase 1: Attack Surface Mapper
Maps trust boundaries, authentication requirements, and prioritizes endpoints
for dynamic exploitation.
"""

from typing import Dict, Any, List


class SurfaceMapper:
    """Constructs a structured attack surface model from static code analysis."""

    @staticmethod
    def map_attack_surface(static_results: Dict[str, Any]) -> Dict[str, Any]:
        routes = static_results.get("routes", [])
        risk_flags = static_results.get("risk_flags", [])

        public_endpoints = []
        authenticated_endpoints = []
        object_endpoints = []
        search_endpoints = []

        for r in routes:
            path = r.get("path", "")
            method = r.get("method", "GET")
            endpoint_item = {
                "path": path,
                "method": method,
                "file": r.get("file", ""),
                "parameters": r.get("parameters", [])
            }

            if "auth" in path or "login" in path or "health" in path:
                public_endpoints.append(endpoint_item)
            elif "search" in path:
                search_endpoints.append(endpoint_item)
            elif r.get("has_parameters", False):
                object_endpoints.append(endpoint_item)
                authenticated_endpoints.append(endpoint_item)
            else:
                authenticated_endpoints.append(endpoint_item)

        # Map prioritized exploitation targets
        prioritized_targets = []
        for r in object_endpoints:
            prioritized_targets.append({
                "category": "IDOR_BOLA",
                "target_path": r["path"],
                "method": r["method"],
                "reason": "Parameterized direct object access endpoint; test cross-tenant unauthorized access."
            })

        for r in search_endpoints:
            prioritized_targets.append({
                "category": "SQL_INJECTION",
                "target_path": r["path"],
                "method": r["method"],
                "reason": "Query parameter endpoint; test for SQL syntax breakout and data exfiltration."
            })

        return {
            "total_routes": len(routes),
            "frameworks": static_results.get("frameworks", []),
            "public_endpoints": public_endpoints,
            "authenticated_endpoints": authenticated_endpoints,
            "object_endpoints": object_endpoints,
            "search_endpoints": search_endpoints,
            "prioritized_targets": prioritized_targets,
            "code_risk_count": len(risk_flags)
        }
