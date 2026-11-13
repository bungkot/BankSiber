"""Research tooling must work headlessly and report consistent data."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from securebank_lab.core.config import Mode
from securebank_lab.research.analyzer import (
    ResearchAnalyzer,
    run_research_analysis,
)
from securebank_lab.research.cli import main as research_main
from securebank_lab.research.cli import threat_model_main
from securebank_lab.research.threat_model import ThreatModelBuilder
from securebank_lab.storage.database import init_db


@pytest.fixture
def seeded_db(tmp_path: Path) -> Callable[[Mode], Path]:
    """Return a factory seeding an isolated per-mode database."""

    def _make(mode: Mode) -> Path:
        path = tmp_path / f"{mode.value}.db"
        init_db(path, mode)
        return path

    return _make


def test_analyzer_confirms_flaws_in_vulnerable_mode(
    seeded_db: Callable[[Mode], Path],
) -> None:
    analyzer = ResearchAnalyzer(
        Mode.VULNERABLE, database_path=seeded_db(Mode.VULNERABLE)
    )
    findings = analyzer.enumerate_vulnerabilities()
    assert findings, "vulnerable mode must produce findings"
    assert all(f.status == "confirmed" for f in findings)
    assert any(f.severity == "Critical" for f in findings)


def test_analyzer_reports_mitigations_in_secure_mode(
    seeded_db: Callable[[Mode], Path],
) -> None:
    analyzer = ResearchAnalyzer(Mode.SECURE, database_path=seeded_db(Mode.SECURE))
    findings = analyzer.enumerate_vulnerabilities()
    assert findings
    assert all(f.status == "mitigated" for f in findings)


def test_analyzer_finds_foreign_keys(seeded_db: Callable[[Mode], Path]) -> None:
    analyzer = ResearchAnalyzer(Mode.SECURE, database_path=seeded_db(Mode.SECURE))
    schema = analyzer.analyze_database_schema()
    fk_targets = {fk["references"] for fk in schema["foreign_keys"]}
    assert "users.id" in fk_targets
    assert "accounts.id" in fk_targets


def test_research_report_serialises_to_json(seeded_db: Callable[[Mode], Path]) -> None:
    report = run_research_analysis(
        Mode.VULNERABLE, database_path=seeded_db(Mode.VULNERABLE)
    )
    data = json.loads(report.to_json())
    assert data["mode"] == "vulnerable"
    assert data["findings"]
    assert data["attack_surface"]["total_endpoints"] > 0


def test_research_output_file(
    seeded_db: Callable[[Mode], Path], tmp_path: Path
) -> None:
    out = tmp_path / "reports" / "posture.json"
    run_research_analysis(
        Mode.SECURE, database_path=seeded_db(Mode.SECURE), output_path=out
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["mode"] == "secure"
    assert all(f["status"] == "mitigated" for f in data["findings"])


def test_threat_model_derives_actors_and_risks(
    seeded_db: Callable[[Mode], Path],
) -> None:
    model = ThreatModelBuilder(
        Mode.VULNERABLE, database_path=seeded_db(Mode.VULNERABLE)
    ).build_threat_model()
    assert model.threat_actors
    assert model.attack_vectors
    assert model.risk_assessment
    # Confirmed flaws must score at full weight (not the mitigated 0.3).
    assert max(model.risk_assessment.values()) >= 0.9


def test_threat_model_residual_risks_distinguish_status(
    seeded_db: Callable[[Mode], Path],
) -> None:
    vuln = ThreatModelBuilder(
        Mode.VULNERABLE, database_path=seeded_db(Mode.VULNERABLE)
    ).build_threat_model()
    secure = ThreatModelBuilder(
        Mode.SECURE, database_path=seeded_db(Mode.SECURE)
    ).build_threat_model()
    assert any(r.startswith("Active risk") for r in vuln.residual_risks)
    assert any(r.startswith("Residual risk") for r in secure.residual_risks)
    assert not any(r.startswith("Active risk") for r in secure.residual_risks)


def test_research_cli_writes_report(
    seeded_db: Callable[[Mode], Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "out.json"
    code = research_main(
        [
            "--mode",
            "secure",
            "--database",
            str(seeded_db(Mode.SECURE)),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["mode"] == "secure"


def test_threat_model_cli_writes_model(
    seeded_db: Callable[[Mode], Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "tm.json"
    code = threat_model_main(
        [
            "--mode",
            "vulnerable",
            "--database",
            str(seeded_db(Mode.VULNERABLE)),
            "--output",
            str(out),
        ]
    )
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["mode"] == "vulnerable"
    assert data["threat_actors"]
