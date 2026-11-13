"""A07 Authentication Failures and A04 Cryptographic Failures."""

from __future__ import annotations

from pathlib import Path

from flask import Flask
from flask.testing import FlaskClient

from securebank_lab.banking.secure import (
    LOCKOUT_SECONDS,
    MAX_FAILED_ATTEMPTS,
    SecureAccountService,
)
from securebank_lab.core.config import Mode
from securebank_lab.storage.database import DEMO_CREDENTIALS, connect, init_db
from tests.conftest import login


def test_vulnerable_accepts_published_default_credentials(vuln: FlaskClient) -> None:
    assert login(vuln, Mode.VULNERABLE, "admin", "admin").status_code == 302


def test_secure_rejects_default_credentials(secure: FlaskClient) -> None:
    assert login(secure, Mode.SECURE, "admin", "admin").status_code == 401


def test_vulnerable_has_no_lockout(vuln: FlaskClient) -> None:
    for _ in range(MAX_FAILED_ATTEMPTS + 3):
        login(vuln, Mode.VULNERABLE, "jsmith", "wrong")
    assert login(vuln, Mode.VULNERABLE, "jsmith").status_code == 302


def test_secure_locks_account_after_repeated_failures(secure: FlaskClient) -> None:
    for _ in range(MAX_FAILED_ATTEMPTS):
        login(secure, Mode.SECURE, "jsmith", "wrong")
    # Even the CORRECT password is refused while locked, with a generic message.
    response = login(secure, Mode.SECURE, "jsmith")
    assert response.status_code == 401
    assert "temporarily locked" in response.get_data(as_text=True)


def test_secure_lockout_expires(tmp_path: Path) -> None:
    db = tmp_path / "lock.db"
    init_db(db, Mode.SECURE)
    now = [1_000.0]
    service = SecureAccountService(connect(db), clock=lambda: now[0])
    good = DEMO_CREDENTIALS[Mode.SECURE]["jsmith"]

    for _ in range(MAX_FAILED_ATTEMPTS):
        service.authenticate("jsmith", "wrong")
    now[0] += LOCKOUT_SECONDS + 1
    assert service.authenticate("jsmith", good) is not None


def test_passwords_are_plaintext_only_in_vulnerable_mode(
    vuln_app: Flask, secure_app: Flask
) -> None:
    def stored(app: Flask) -> str:
        conn = connect(app.config["SETTINGS"].resolved_database_path)
        try:
            return str(
                conn.execute(
                    "SELECT password FROM users WHERE username='admin'"
                ).fetchone()["password"]
            )
        finally:
            conn.close()

    assert stored(vuln_app) == "admin"
    assert stored(secure_app).startswith(("scrypt:", "pbkdf2:"))


def test_secure_login_issues_a_fresh_session(secure: FlaskClient) -> None:
    before = secure.get("/login").headers.get("Set-Cookie", "")
    after = login(secure, Mode.SECURE, "jsmith").headers.get("Set-Cookie", "")
    assert before != after
