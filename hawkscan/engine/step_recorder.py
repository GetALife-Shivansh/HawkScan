"""HawkScan Step-by-Step Exploit Action Recorder
Maintains chronological playback traces for browser-driven vulnerability validations,
cookie security investigations, and automated proof generation.
"""

import time
from typing import List, Dict, Any, Optional


class ActionStep:
    """Represents a discrete action executed during a browser exploit sequence."""

    def __init__(
        self,
        step_number: int,
        action: str,
        target: str,
        details: str,
        status: str = "SUCCESS",
        timestamp: Optional[float] = None,
        screenshot_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.step_number = step_number
        self.action = action.upper().strip()
        self.target = target
        self.details = details
        self.status = status.upper().strip()
        self.timestamp = timestamp or time.time()
        self.screenshot_path = screenshot_path
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "step": self.step_number,
            "action": self.action,
            "target": self.target,
            "details": self.details,
            "status": self.status,
            "timestamp": round(self.timestamp, 3),
        }
        if self.screenshot_path:
            data["screenshot_path"] = self.screenshot_path
        if self.metadata:
            data["metadata"] = self.metadata
        return data


class StepRecorder:
    """Records an ordered sequence of exploit actions and formats them for reporting and UI."""

    def __init__(self, agent_name: str = "BrowserExploitAgent"):
        self.agent_name = agent_name
        self.steps: List[ActionStep] = []

    def record_step(
        self,
        action: str,
        target: str,
        details: str,
        status: str = "SUCCESS",
        screenshot_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Appends a new chronological action step."""
        step_number = len(self.steps) + 1
        step = ActionStep(
            step_number=step_number,
            action=action,
            target=target,
            details=details,
            status=status,
            screenshot_path=screenshot_path,
            metadata=metadata,
        )
        self.steps.append(step)
        return step.to_dict()

    def get_steps(self) -> List[Dict[str, Any]]:
        """Returns the list of recorded steps as serialized dictionaries."""
        return [s.to_dict() for s in self.steps]

    def to_markdown_table(self) -> str:
        """Renders the recorded steps as a GitHub Flavored Markdown table."""
        if not self.steps:
            return "*No sequential actions recorded.*"

        rows = [
            "| Step | Action | Target / Context | Details | Status |",
            "| :---: | :--- | :--- | :--- | :--- |",
        ]
        for s in self.steps:
            status_badge = f"`{s.status}`"
            if s.status in ("SUCCESS", "BREACH_CONFIRMED"):
                status_badge = f"✅ `{s.status}`"
            elif "WARN" in s.status:
                status_badge = f"⚠️ `{s.status}`"
            elif s.status == "FAILED":
                status_badge = f"❌ `{s.status}`"

            clean_target = s.target.replace("|", "\\|")
            clean_details = s.details.replace("|", "\\|")
            rows.append(
                f"| {s.step_number} | **{s.action}** | `{clean_target}` | {clean_details} | {status_badge} |"
            )

        return "\n".join(rows)

    def clear(self):
        """Clears all recorded steps."""
        self.steps = []
