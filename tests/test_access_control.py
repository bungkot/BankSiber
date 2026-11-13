"""A01 Broken Access Control (IDOR)."""

from __future__ import annotations

from flask.testing import FlaskClient

from securebank_lab.core.config import Mode
from tests.conftest import login

FOREIGN_ACCOUNT = 1002  # owned by sgreen


def test_vulnerable_idor_exposes_other_customers_ledger(vuln: FlaskClient) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    response = vuln.get(f"/accounts/{FOREIGN_ACCOUNT}/transactions")
    assert response.status_code == 200
    assert "Confidential: tax payment" in response.get_data(as_text=True)


def test_secure_denies_other_customers_ledger(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    assert secure.get(f"/accounts/{FOREIGN_ACCOUNT}/transactions").status_code == 404


def test_secure_allows_own_ledger(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    response = secure.get("/accounts/1001/transactions")
    assert response.status_code == 200
    assert "Salary March" in response.get_data(as_text=True)


def test_secure_unknown_and_foreign_accounts_look_identical(
    secure: FlaskClient,
) -> None:
    login(secure, Mode.SECURE, "jsmith")
    foreign = secure.get(f"/accounts/{FOREIGN_ACCOUNT}/transactions")
    missing = secure.get("/accounts/9999/transactions")
    assert foreign.status_code == missing.status_code == 404  # no enumeration


def test_anonymous_users_are_redirected_to_login(secure: FlaskClient) -> None:
    response = secure.get("/accounts/1001/transactions")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
