"""HawkScan: Autonomous White-Box AI Pentester Package
Proof-by-Exploitation AI Pentester: No Exploit, No Report.
"""

from hawkscan.config import settings
from hawkscan.orchestrator.pipeline import HawkScanPipeline

# Backwards compatibility alias
ShannonPipeline = HawkScanPipeline

__all__ = ["settings", "HawkScanPipeline", "ShannonPipeline"]
