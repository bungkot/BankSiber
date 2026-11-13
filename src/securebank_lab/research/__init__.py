"""Research package: attack-surface analysis and threat modelling.

Headless tooling that operates on either lab implementation without a
running web server:

* :mod:`securebank_lab.research.analyzer` - security posture and findings
  enumeration (``securebank-research``).
* :mod:`securebank_lab.research.threat_model` - actor profiles, attack
  vectors and risk scoring (``securebank-threat-model``).
"""

from __future__ import annotations

from securebank_lab.research.analyzer import (
    AttackSurface,
    ResearchAnalyzer,
    ResearchReport,
    VulnerabilityFinding,
    run_research_analysis,
)
from securebank_lab.research.threat_model import (
    AttackVector,
    ThreatActor,
    ThreatModel,
    ThreatModelBuilder,
    run_threat_modeling,
)

__all__ = [
    "AttackSurface",
    "AttackVector",
    "ResearchAnalyzer",
    "ResearchReport",
    "ThreatActor",
    "ThreatModel",
    "ThreatModelBuilder",
    "VulnerabilityFinding",
    "run_research_analysis",
    "run_threat_modeling",
]
