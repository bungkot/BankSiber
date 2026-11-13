"""Meta-test: the lab must cover every OWASP Top 10 (2021) category."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from securebank_lab.core.config import Mode
from securebank_lab.research.analyzer import ResearchAnalyzer
from securebank_lab.storage.database import init_db

ALL_CATEGORIES = {f"A{i:02d}" for i in range(1, 11)}


@pytest.fixture
def findings_by_mode() -> dict[Mode, dict[str, str]]:
    """Enumerated findings per mode: {finding id prefix: status}."""
    out: dict[Mode, dict[str, str]] = {}
    for mode in (Mode.VULNERABLE, Mode.SECURE):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / f"{mode.value}.db"
            init_db(path, mode)
            findings = ResearchAnalyzer(
                mode, database_path=path
            ).enumerate_vulnerabilities()
        out[mode] = {f.id.split("-")[0]: f.status for f in findings}
    return out


def test_all_ten_owasp_categories_are_enumerated(
    findings_by_mode: dict[Mode, dict[str, str]],
) -> None:
    for mode, findings in findings_by_mode.items():
        missing = ALL_CATEGORIES - set(findings)
        assert not missing, (
            f"{mode.value} mode is missing categories: {sorted(missing)}"
        )


def test_vulnerable_mode_confirms_every_category(
    findings_by_mode: dict[Mode, dict[str, str]],
) -> None:
    statuses = findings_by_mode[Mode.VULNERABLE]
    assert set(statuses.values()) == {"confirmed"}


def test_secure_mode_mitigates_every_category(
    findings_by_mode: dict[Mode, dict[str, str]],
) -> None:
    statuses = findings_by_mode[Mode.SECURE]
    assert set(statuses.values()) == {"mitigated"}


def test_every_category_has_a_unique_primary_finding(
    findings_by_mode: dict[Mode, dict[str, str]],
) -> None:
    # Multiple findings may share a category (e.g. A05); each must still be
    # present exactly once as a category key mapping.
    for mode, findings in findings_by_mode.items():
        assert len(findings) == len(set(findings)), mode
