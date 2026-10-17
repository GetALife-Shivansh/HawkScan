"""HawkScan Phase 4: Proof-by-Exploitation Validator ("No Exploit, No Report")
Enforces strict proof requirements: only vulnerabilities verified by live
working execution against the target are admitted into the final dossier.
"""

from typing import List, Dict, Any, Optional, Callable


class ProofValidator:
    """Validates proof-of-concept execution results and discards false positives."""

    def __init__(self, emit_fn: Optional[Callable[[str, str], Any]] = None):
        self.emit_fn = emit_fn

    def log(self, msg: str):
        if self.emit_fn:
            self.emit_fn("validation", msg)

    def validate_and_filter(
        self,
        exploit_results: List[Optional[Dict[str, Any]]],
        static_risk_flags: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Separates verified, proven exploits from discarded theoretical candidates.
        
        Returns:
            (verified_exploits, discarded_false_positives)
        """
        self.log("Phase 4: Enforcing 'No Exploit, No Report' proof validation...")

        verified = []
        discarded = []

        # 1. Filter live exploit outcomes
        for res in exploit_results:
            if not res:
                continue

            poc = res.get("proof_of_concept", {})
            http_status = poc.get("http_status")
            has_command = bool(poc.get("exploit_command"))
            has_evidence = bool(poc.get("leaked_payload") or poc.get("evidence_summary"))

            # Strict validation rule: must succeed (200/201), have reproducible command, actual leaked payload, and not be marked UNVERIFIED
            is_verified = (
                res.get("status") != "UNVERIFIED" and
                http_status in (200, 201) and
                has_command and
                bool(poc.get("leaked_payload"))
            )

            if is_verified:
                res["validation_status"] = "PROVEN_BY_EXPLOITATION"
                verified.append(res)
                self.log(f"VERIFIED: {res['title']} (CWE: {res.get('cwe_id')}) proven by working PoC.")
            else:
                discarded.append({
                    "title": res.get("title", "Exploit Candidate"),
                    "reason": poc.get("evidence_summary") or f"Probe returned HTTP {http_status}; did not achieve confirmed breach.",
                    "status": "DISCARDED_FALSE_POSITIVE"
                })

        # 2. Account for static warnings that had no live exploit
        verified_types = {v.get("cwe_id") for v in verified}
        for flag in static_risk_flags:
            flag_type = flag.get("type", "")
            # If static risk wasn't converted into a verified exploit, log as discarded theoretical hunch
            if flag_type == "IDOR_BOLA_CANDIDATE" and "CWE-639" not in verified_types:
                discarded.append({
                    "title": "Static IDOR Warning",
                    "file": flag.get("file"),
                    "reason": "Static code flag could not be breached dynamically against live target.",
                    "status": "DISCARDED_FALSE_POSITIVE"
                })

        self.log(
            f"Validation complete: {len(verified)} verified vulnerability/ies substantiated with working exploit; "
            f"{len(discarded)} theoretical candidate(s) discarded."
        )

        return verified, discarded
