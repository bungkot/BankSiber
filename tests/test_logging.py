"""A09: security logging — silent vulnerable mode vs structured audit trail."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from securebank_lab.core.config import Mode
from securebank_lab.research.analyzer import ResearchAnalyzer
from securebank_lab.storage.database import init_db
from tests.conftest import login

_SECURE_PASSWORD = "Cx7!mango-orbit"
_VULN_PASSWORD = "demo1234"


def _audit_records(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "securebank.audit"]


def test_vulnerable_mode_logs_no_security_events(
    vuln: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="securebank.audit")
    login(vuln, Mode.VULNERABLE, "jsmith", "wrong-password")
    login(vuln, Mode.VULNERABLE, "jsmith", _VULN_PASSWORD)
    vuln.get("/accounts/9999/transactions")
    assert _audit_records(caplog) == []


def test_secure_mode_logs_auth_and_denial_events(
    secure: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="securebank.audit")
    login(secure, Mode.SECURE, "jsmith", "wrong-password")
    login(secure, Mode.SECURE, "jsmith", _SECURE_PASSWORD)
    secure.get("/accounts/9999/transactions")
    messages = "\n".join(_audit_records(caplog))
    assert "login_failed" in messages
    assert "login_ok" in messages
    assert "access_denied" in messages


def test_secure_mode_logs_rejected_ssrf(
    secure: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="securebank.audit")
    login(secure, Mode.SECURE, "jsmith", _SECURE_PASSWORD)
    secure.get("/import/statement?url=file:///etc/passwd")
    messages = "\n".join(_audit_records(caplog))
    assert "import_rejected" in messages
    assert re.search(r"file:", messages)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [(Mode.VULNERABLE, "disabled"), (Mode.SECURE, "enabled")],
)
def test_research_analyzer_reports_logging_posture(
    mode: Mode, expected: str, tmp_path: Path
) -> None:
    path = tmp_path / f"{mode.value}.db"
    init_db(path, mode)
    posture = ResearchAnalyzer(mode, database_path=path).analyze_logging()
    assert posture["security_event_logging"] == expected
