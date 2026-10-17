"""HawkScan Phase 5: OASIS SARIF 2.1.0 Report Generator
Produces standardized SARIF output for GitHub Security / GitLab DAST pipelines.
"""

from typing import List, Dict, Any


class SarifGenerator:
    """Formats verified penetration testing vulnerabilities into OASIS SARIF 2.1.0 schema."""

    @staticmethod
    def generate_sarif(verified_vulnerabilities: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
        rules = []
        results = []

        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note"
        }

        for i, vuln in enumerate(verified_vulnerabilities):
            rule_id = vuln.get("vulnerability_id", f"HAWKSCAN-VULN-{i+1}")
            cwe = vuln.get("cwe_id", "CWE-General")
            owasp = vuln.get("owasp_category", "OWASP Top 10")
            title = vuln.get("title", "Discovered Vulnerability")

            rules.append({
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": vuln.get("description", title)},
                "help": {
                    "text": f"Remediation: {vuln.get('remediation', {}).get('guidance', 'Apply security patch.')}"
                },
                "properties": {
                    "tags": ["security", "pentest", cwe, owasp],
                    "precision": "very-high" # Proven by exploitation
                }
            })

            target_file = vuln.get("remediation", {}).get("target_file", "app.py")
            poc = vuln.get("proof_of_concept", {})

            results.append({
                "ruleId": rule_id,
                "ruleIndex": i,
                "level": level_map.get(vuln.get("severity", "MEDIUM"), "warning"),
                "message": {
                    "text": f"{title} verified against endpoint {vuln.get('target_endpoint')}. {poc.get('evidence_summary', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_file},
                            "region": {"startLine": 1}
                        }
                    }
                ],
                "properties": {
                    "severity": vuln.get("severity"),
                    "exploit_command": poc.get("exploit_command", ""),
                    "target_url": target_url,
                    **({"cookie_audit": vuln["cookie_audit"]} if vuln.get("cookie_audit") else {}),
                    **({"recorded_steps": vuln["recorded_steps"]} if vuln.get("recorded_steps") else {})
                }
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HawkScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/HawkScan/hawkscan",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }
