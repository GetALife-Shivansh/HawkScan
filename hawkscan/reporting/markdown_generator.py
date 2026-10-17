"""HawkScan Phase 5: Markdown Penetration Testing Report Generator"""

import time
from typing import List, Dict, Any


class MarkdownGenerator:
    """Generates professional Markdown audit reports detailing proven vulnerabilities and PoCs."""

    @staticmethod
    def generate_report(
        scan_metadata: Dict[str, Any],
        verified_vulnerabilities: List[Dict[str, Any]],
        discarded_false_positives: List[Dict[str, Any]]
    ) -> str:
        date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        target_url = scan_metadata.get("target_url", "http://127.0.0.1:8000")
        repo_path = scan_metadata.get("repo_path", ".")
        duration = scan_metadata.get("duration_seconds", 0)

        lines = [
            "# 🦅 HawkScan Autonomous AI Penetration Testing Report",
            f"**Audit Execution Date:** {date_str}  ",
            f"**Target URL:** `{target_url}`  ",
            f"**Repository Analyzed:** `{repo_path}`  ",
            f"**Assessment Duration:** `{duration}s`  ",
            f"**Methodology:** White-Box Static Code Analysis + Dynamic Exploitation (Proof-by-Exploitation)  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"HawkScan conducted an autonomous white-box penetration test against `{target_url}` using source repository `{repo_path}`. "
            f"Operating under the **'No Exploit, No Report'** doctrine, HawkScan only reports vulnerabilities that were actively substantiated by executing a working Proof-of-Concept against the running application.",
            "",
            f"- **Verified Exploitable Vulnerabilities:** `{len(verified_vulnerabilities)}`",
            f"- **Discarded Theoretical Candidates / False Positives:** `{len(discarded_false_positives)}`",
            "",
            "| ID | Vulnerability Title | Severity | CWE | OWASP Top 10 | Target Endpoint |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if not verified_vulnerabilities:
            lines.append("| - | *No exploitable vulnerabilities confirmed* | - | - | - | - |")
        else:
            for v in verified_vulnerabilities:
                lines.append(
                    f"| `{v.get('vulnerability_id')}` | **{v.get('title')}** | `{v.get('severity')}` | `{v.get('cwe_id')}` | {v.get('owasp_category')} | `{v.get('target_endpoint')}` |"
                )

        lines.extend([
            "",
            "---",
            "",
            "## 2. Verified Vulnerabilities & Working Proofs of Concept",
            ""
        ])

        for v in verified_vulnerabilities:
            poc = v.get("proof_of_concept", {})
            remediation = v.get("remediation", {})
            lines.extend([
                f"### {v.get('title')} (`{v.get('vulnerability_id')}`)",
                f"- **Severity:** `{v.get('severity')}`",
                f"- **CWE:** `{v.get('cwe_id')}` | **OWASP:** `{v.get('owasp_category')}`",
                f"- **Affected Endpoint:** `{v.get('target_endpoint')}` (`{v.get('http_method')}`)",
                f"- **Vulnerable Source File:** `{remediation.get('target_file', 'app.py')}`",
                "",
                "#### Description & Impact",
                v.get("description", "Vulnerability verified by dynamic exploitation."),
                "",
                "#### Reproducible Proof-of-Concept (curl)",
                "```bash",
                poc.get("exploit_command", "# Exploit command"),
                "```",
                "",
                "#### Captured Evidence & Proof Payload",
                f"**HTTP Response Status:** `{poc.get('http_status')}`",
                "```json",
                f"{poc.get('leaked_payload', {})}",
                "```",
                f"> **Proof Summary:** {poc.get('evidence_summary', 'Exploit succeeded.')}",
                "",
                "#### Developer Remediation Guidance",
                f"{remediation.get('guidance', 'Apply defensive access control checks.')}",
                "",
                "---",
                ""
            ])

        lines.extend([
            "## 3. Discarded Theoretical Candidates (False Positives Suppressed)",
            "",
            "To prevent developer fatigue, HawkScan suppresses unverified alerts that could not breach the live environment:",
            ""
        ])

        if not discarded_false_positives:
            lines.append("- *No theoretical candidates discarded.*")
        else:
            for d in discarded_false_positives:
                lines.append(f"- **{d.get('title')}:** {d.get('reason')} (`{d.get('status')}`)")

        lines.extend([
            "",
            "---",
            "*Report generated autonomously by HawkScan AI Pentester.*"
        ])

        return "\n".join(lines)
