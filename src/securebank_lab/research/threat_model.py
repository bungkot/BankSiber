"""Threat modeling utilities for the SecureBank Lab.

Provides structured threat modelling (actor profiles, attack vectors, risk
scoring and residual-risk identification) built on top of the findings
enumerated by :mod:`securebank_lab.research.analyzer`.

Methodology references: OWASP Top 10, OWASP ASVS, NIST SP 800-30.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securebank_lab.core.config import Mode
from securebank_lab.research.analyzer import (
    ResearchAnalyzer,
    VulnerabilityFinding,
)

_SEVERITY_SCORE = {"Critical": 9.0, "High": 7.0, "Medium": 5.0, "Low": 3.0}


@dataclass(frozen=True, slots=True)
class ThreatActor:
    """A potential threat-actor profile for threat modelling."""

    id: str
    name: str
    skill_level: str  # "script_kiddie", "competent", "advanced", "APT"
    motivation: str  # "financial", "data_theft", "disruption", "research"
    capabilities: tuple[str, ...]  # e.g. ("sql_injection", "credential_stuffing")
    attack_surface_focus: tuple[str, ...]  # e.g. ("authentication", "input_validation")


@dataclass(frozen=True, slots=True)
class AttackVector:
    """A documented attack vector with severity and mitigation status."""

    id: str
    title: str
    category: str
    owasp_ref: str  # e.g. "A03"
    description: str
    exploit_difficulty: str  # "low", "medium", "high"
    success_condition: str
    impact: str
    current_status: str  # "confirmed", "mitigated"
    mitigation: str


@dataclass(frozen=True, slots=True)
class ThreatModel:
    """A complete threat model for one mode of the lab."""

    mode: Mode
    generated_at: datetime
    threat_actors: tuple[ThreatActor, ...]
    attack_vectors: tuple[AttackVector, ...]
    risk_assessment: dict[str, float]  # category -> risk score 0.0-1.0
    residual_risks: tuple[str, ...]
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the model."""
        return {
            "mode": self.mode.value,
            "generated_at": self.generated_at.isoformat(),
            "threat_actors": [asdict(a) for a in self.threat_actors],
            "attack_vectors": [asdict(v) for v in self.attack_vectors],
            "risk_assessment": self.risk_assessment,
            "residual_risks": list(self.residual_risks),
            "recommendations": list(self.recommendations),
        }


class ThreatModelBuilder:
    """Build a comprehensive threat model for a SecureBank Lab mode."""

    def __init__(self, mode: Mode, database_path: Path | None = None) -> None:
        self.mode = mode
        self.database_path = database_path
        self._analyzer: ResearchAnalyzer | None = None

    @property
    def analyzer(self) -> ResearchAnalyzer:
        """Lazily created analyzer for the configured mode."""
        if self._analyzer is None:
            self._analyzer = ResearchAnalyzer(
                self.mode, database_path=self.database_path
            )
        return self._analyzer

    def build_threat_model(self) -> ThreatModel:
        """Construct a full threat model for the current mode."""
        findings = self.analyzer.enumerate_vulnerabilities()
        actors = self._derive_threat_actors(findings)
        vectors = self._derive_attack_vectors(findings)
        risk = self._compute_risk_assessment(findings, vectors)
        residual = self._identify_residual_risks(findings)
        recommendations = self._generate_recommendations(findings, vectors)
        return ThreatModel(
            mode=self.mode,
            generated_at=datetime.now(timezone.utc),
            threat_actors=actors,
            attack_vectors=vectors,
            risk_assessment=risk,
            residual_risks=residual,
            recommendations=recommendations,
        )

    @staticmethod
    def _derive_threat_actors(
        findings: tuple[VulnerabilityFinding, ...],
    ) -> tuple[ThreatActor, ...]:
        """Derive relevant threat-actor profiles from the findings."""
        actors: list[ThreatActor] = []
        if any(f.category == "Injection" for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-001",
                    name="Data Extractor",
                    skill_level="competent",
                    motivation="data_theft",
                    capabilities=("sql_injection", "union_based", "error_based"),
                    attack_surface_focus=("input_validation", "search_endpoint"),
                )
            )
        if any("Lockout" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-002",
                    name="Credential Brute-Forcer",
                    skill_level="script_kiddie",
                    motivation="unauthorized_access",
                    capabilities=("brute_force", "credential_stuffing"),
                    attack_surface_focus=(
                        "authentication_endpoint",
                        "session_management",
                    ),
                )
            )
        if any("Plaintext" in f.title or "Secret Key" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-003",
                    name="Session Hijacker",
                    skill_level="competent",
                    motivation="unauthorized_access",
                    capabilities=("session_fixation", "cookie_manipulation", "csrf"),
                    attack_surface_focus=("session_management", "csrf_protection"),
                )
            )
        if any("Direct Object" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-004",
                    name="Privilege Escalator",
                    skill_level="competent",
                    motivation="data_theft",
                    capabilities=("idor", "object_reference_manipulation"),
                    attack_surface_focus=("access_control", "authorization_endpoints"),
                )
            )
        if any("Error" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-005",
                    name="Reconnaissance Actor",
                    skill_level="script_kiddie",
                    motivation="information_gathering",
                    capabilities=("error_analysis", "stack_trace_analysis"),
                    attack_surface_focus=("error_handling", "api_endpoints"),
                )
            )
        if any(
            "Version Disclosure" in f.title or "Outdated" in f.title for f in findings
        ):
            actors.append(
                ThreatActor(
                    id="TA-006",
                    name="Component Reconnaissance",
                    skill_level="script_kiddie",
                    motivation="information_gathering",
                    capabilities=("version_fingerprinting", "dependency_analysis"),
                    attack_surface_focus=("component_inventory", "info_endpoints"),
                )
            )
        if any("Integrity" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-007",
                    name="Data Meddler",
                    skill_level="competent",
                    motivation="financial",
                    capabilities=("export_tampering", "stamp_forgery"),
                    attack_surface_focus=("exports", "data_integrity"),
                )
            )
        if any("Request Forgery" in f.title for f in findings):
            actors.append(
                ThreatActor(
                    id="TA-008",
                    name="Internal Service Prober",
                    skill_level="competent",
                    motivation="information_gathering",
                    capabilities=("ssrf", "file_scheme_abuse", "internal_scanning"),
                    attack_surface_focus=("url_fetchers", "import_endpoints"),
                )
            )
        return tuple(actors)

    @staticmethod
    def _derive_attack_vectors(
        findings: tuple[VulnerabilityFinding, ...],
    ) -> tuple[AttackVector, ...]:
        """Map each finding to one primary and one secondary attack vector."""
        vectors: list[AttackVector] = []
        for f in findings:
            owasp_ref = f.id.split("-")[0] if "-" in f.id else "A99"
            difficulty = _difficulty_for(f.severity)
            vectors.append(
                AttackVector(
                    id=f.id,
                    title=f.title,
                    category=f.category,
                    owasp_ref=owasp_ref,
                    description=f.evidence,
                    exploit_difficulty=difficulty,
                    success_condition=_success_condition(f),
                    impact=_impact(f),
                    current_status=f.status,
                    mitigation=f.recommendation,
                )
            )
            vectors.append(
                AttackVector(
                    id=f"{f.id}-secondary",
                    title=f"{f.title} - Secondary Effects",
                    category=f"{f.category} (secondary)",
                    owasp_ref=owasp_ref,
                    description=(
                        f"Secondary consequences of {f.title.lower()}; may lead to "
                        "data corruption, privilege escalation or service disruption"
                    ),
                    exploit_difficulty=difficulty,
                    success_condition=_secondary_success_condition(f),
                    impact=_secondary_impact(f),
                    current_status=f.status,
                    mitigation=f"{f.recommendation} (also prevents secondary effects)",
                )
            )
        return tuple(vectors)

    @staticmethod
    def _compute_risk_assessment(
        findings: tuple[VulnerabilityFinding, ...],
        vectors: tuple[AttackVector, ...],
    ) -> dict[str, float]:
        """Compute per-category risk scores (0.0 = none, 1.0 = critical)."""
        severity_by_id = {f.id: f.severity for f in findings}
        categories: dict[str, list[float]] = {}
        for v in vectors:
            base_id = v.id.removesuffix("-secondary")
            severity = severity_by_id.get(base_id, "Medium")
            status_weight = 1.0 if v.current_status == "confirmed" else 0.3
            score = _SEVERITY_SCORE.get(severity, 5.0) / 10.0 * status_weight
            if v.id.endswith("-secondary"):
                score *= 0.5  # secondary effects carry half the weight
            categories.setdefault(v.category, []).append(score)

        return {
            cat: round(sum(scores) / len(scores), 2)
            for cat, scores in categories.items()
            if scores
        }

    @staticmethod
    def _identify_residual_risks(
        findings: tuple[VulnerabilityFinding, ...],
    ) -> tuple[str, ...]:
        """Identify risks that remain even after documented mitigations."""
        risks: list[str] = []
        for f in findings:
            if f.status == "mitigated":
                risks.append(f"Residual risk: {f.title} - {f.recommendation}")
            else:
                risks.append(f"Active risk: {f.title} - exploit is confirmed feasible")
        return tuple(risks)

    @staticmethod
    def _generate_recommendations(
        findings: tuple[VulnerabilityFinding, ...],
        vectors: tuple[AttackVector, ...],
    ) -> tuple[str, ...]:
        """Generate prioritised, de-duplicated recommendations."""
        recs: set[str] = set()
        for f in findings:
            if f.recommendation:
                recs.add(f.recommendation)
        for v in vectors:
            if v.mitigation:
                recs.add(v.mitigation)
        recs.update(
            {
                "Implement security headers (CSP, HSTS, "
                "X-Content-Type-Options) on all responses",
                "Rotate all default/demo credentials before any research deployment",
                "Enable HTTPS with a valid TLS certificate for production deployments",
                "Configure cookie flags (HttpOnly, Secure, SameSite=Strict) uniformly",
                "Set up centralised audit logging with log-integrity controls",
                "Adopt a threat-modelling process aligned with OWASP ASVS Level 2+",
                "Re-run the assessment after every fix to confirm the control works",
            }
        )
        return tuple(sorted(recs))


def _difficulty_for(severity: str) -> str:
    """Map a finding severity to an exploit-difficulty label."""
    return {"Critical": "low", "High": "medium", "Medium": "medium", "Low": "high"}.get(
        severity, "medium"
    )


def _success_condition(f: VulnerabilityFinding) -> str:
    """Derive the primary success condition from a finding."""
    base = f.evidence.lower()
    if "sql" in base and "inject" in base:
        return "crafted input reaches the vulnerable SQL query without parameterisation"
    if "plaintext" in base or "hash" in base:
        return "obtain a password hash or bypass authentication"
    if "object" in base or "idor" in base:
        return "manipulate an account id parameter to access foreign data"
    if "secret key" in base or "cookie" in base:
        return "forge or tamper with a session cookie"
    if "lockout" in base or "credentials" in base:
        return "guess published default credentials without lockout"
    if "versions" in base or "outdated" in base:
        return "fingerprint components and match them to public exploits"
    if "md5" in base or "stamp" in base or "integrity" in base:
        return "edit an exported ledger and recompute the unkeyed stamp"
    if "importer" in base or "fetch" in base or "url" in base:
        return "make the server fetch file:// or internal http:// resources"
    if "log" in base or "monitoring" in base:
        return "run noisy attacks without any security event being recorded"
    if "error" in base or "trace" in base:
        return "cause an exception and observe the server response"
    return "meet the conditions described in the evidence"


def _impact(f: VulnerabilityFinding) -> str:
    """Derive the primary impact description from a finding."""
    base = f.evidence.lower()
    if "plaintext" in base:
        return "unauthorised disclosure of credentials enabling account takeover"
    if "inject" in base:
        return "unauthorised disclosure of sensitive data (records, balances)"
    if "object" in base:
        return "unauthorised access to another customer's financial data"
    if "secret key" in base:
        return "session forgery leading to full account impersonation"
    if "transfer" in base or "negative" in base:
        return "financial loss via reversed or unlimited transfers"
    if "versions" in base or "outdated" in base:
        return "targeted exploitation of known component weaknesses"
    if "md5" in base or "tamper" in base:
        return "undetectable falsification of financial exports"
    if "importer" in base or "url" in base:
        return "disclosure of internal resources reachable from the server"
    if "log" in base or "monitoring" in base:
        return "attacks proceed undetected with no forensic trail"
    if "error" in base:
        return "information leakage enabling further attacks"
    return "significant security impact"


def _secondary_success_condition(f: VulnerabilityFinding) -> str:
    """Derive the secondary success condition from a finding."""
    base = f.evidence.lower()
    if "sql" in base:
        return "successful SQL injection escalates to full database compromise"
    if "plaintext" in base or "lockout" in base:
        return "authentication bypass enables full account takeover"
    if "transfer" in base or "negative" in base:
        return "unvalidated transfers result in financial fraud"
    if "object" in base:
        return "access to foreign data enables privilege escalation"
    if "md5" in base or "integrity" in base:
        return "tampered exports propagate into downstream systems"
    if "importer" in base or "url" in base:
        return "SSRF pivots to internal services and cloud metadata"
    if "log" in base or "monitoring" in base:
        return "absence of monitoring prolongs intrusions and destroys forensics"
    if "versions" in base or "outdated" in base:
        return "disclosed versions shorten the path to public exploit chains"
    return "secondary effects compound the primary vulnerability"


def _secondary_impact(f: VulnerabilityFinding) -> str:
    """Derive the secondary impact description from a finding."""
    base = f.evidence.lower()
    if "sql" in base:
        return "full database exfiltration, modification or destruction"
    if "plaintext" in base or "lockout" in base:
        return "complete account compromise and potential lateral movement"
    if "transfer" in base or "negative" in base:
        return "unauthorised fund transfers and financial loss"
    if "object" in base:
        return "covert exfiltration from arbitrary user accounts"
    if "md5" in base or "integrity" in base:
        return "corrupted records accepted as genuine by dependent processes"
    if "importer" in base or "url" in base:
        return "internal network foothold for further attacks"
    if "log" in base or "monitoring" in base:
        return "incident detection and response become impossible"
    if "versions" in base or "outdated" in base:
        return "compromise via known, patchable component flaws"
    return "extended security impact beyond the primary finding"


def run_threat_modeling(mode: Mode, database_path: Path | None = None) -> ThreatModel:
    """Convenience function: build a threat model for the given mode."""
    return ThreatModelBuilder(mode, database_path=database_path).build_threat_model()


def render_text(model: ThreatModel) -> str:
    """Render a human-readable threat model summary."""
    lines = [
        f"Threat Model - Mode: {model.mode.value}",
        f"Generated at: {model.generated_at.isoformat()}",
        f"\nThreat Actors ({len(model.threat_actors)}):",
    ]
    for actor in model.threat_actors:
        lines.append(
            f"  - {actor.id}: {actor.name} ({actor.skill_level}, {actor.motivation})"
        )
        lines.append(f"    Capabilities: {', '.join(actor.capabilities)}")
        lines.append(f"    Focus: {', '.join(actor.attack_surface_focus)}")

    lines.append(f"\nAttack Vectors ({len(model.attack_vectors)}):")
    for vector in model.attack_vectors:
        lines.append(f"  - {vector.id}: {vector.title} [{vector.owasp_ref}]")
        lines.append(f"    Status: {vector.current_status}")
        lines.append(f"    Difficulty: {vector.exploit_difficulty}")
        lines.append(f"    Impact: {vector.impact}")

    lines.append("\nRisk Assessment:")
    for category, score in sorted(model.risk_assessment.items(), key=lambda x: -x[1]):
        lines.append(f"  - {category}: {score}/1.0")

    lines.append(f"\nResidual Risks ({len(model.residual_risks)}):")
    lines.extend(f"  - {r}" for r in model.residual_risks)

    lines.append(f"\nRecommendations ({len(model.recommendations)}):")
    lines.extend(f"  {i}. {rec}" for i, rec in enumerate(model.recommendations, 1))
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - direct script use
    import argparse

    parser = argparse.ArgumentParser(description="SecureBank Lab threat modelling tool")
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        required=True,
        help="Which mode to model",
    )
    parser.add_argument(
        "--database", type=Path, default=None, help="Override database path"
    )
    args = parser.parse_args()

    model = run_threat_modeling(
        Mode.VULNERABLE if args.mode == "vulnerable" else Mode.SECURE,
        database_path=args.database,
    )
    print(render_text(model))
