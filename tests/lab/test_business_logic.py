"""A04 Insecure Design and A05-002 verbose error disclosure."""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient

from securebank_lab.banking.secure import MAX_TRANSFER_CENTS, parse_amount_cents
from securebank_lab.core.config import Mode
from securebank_lab.core.exceptions import ValidationError
from securebank_lab.storage.database import schema_for
from tests.conftest import balance, login, post


def _transfer(client: FlaskClient, src: int, dst: int, amount: str):  # type: ignore[no-untyped-def]
    return post(
        client,
        "/transfer",
        {"from_account": str(src), "to_account": str(dst), "amount": amount},
    )


def test_vulnerable_negative_transfer_steals_from_victim(
    vuln: FlaskClient, vuln_app: Flask
) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    victim_before = balance(vuln_app, 1002)
    _transfer(vuln, 1001, 1002, "-500")  # negative amount reverses direction
    assert balance(vuln_app, 1002) == victim_before - 50_000


def test_vulnerable_allows_spending_from_someone_elses_account(
    vuln: FlaskClient, vuln_app: Flask
) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    _transfer(vuln, 1002, 1001, "100")
    assert balance(vuln_app, 1002) == 500_000 - 10_000


def test_secure_rejects_negative_amount(secure: FlaskClient, secure_app: Flask) -> None:
    login(secure, Mode.SECURE, "jsmith")
    response = _transfer(secure, 1001, 1002, "-500")
    assert response.status_code == 400
    assert balance(secure_app, 1002) == 500_000


def test_secure_rejects_foreign_source_account(
    secure: FlaskClient, secure_app: Flask
) -> None:
    login(secure, Mode.SECURE, "jsmith")
    assert _transfer(secure, 1002, 1001, "100").status_code == 404
    assert balance(secure_app, 1002) == 500_000


def test_secure_rejects_overdraft(secure: FlaskClient, secure_app: Flask) -> None:
    login(secure, Mode.SECURE, "jsmith")
    assert _transfer(secure, 1001, 1002, "1499.99").status_code == 302
    assert _transfer(secure, 1001, 1002, "9999.00").status_code == 400
    assert balance(secure_app, 1001) == 1  # one cent left, never negative


def test_secure_transfer_is_atomic_when_destination_is_missing(
    secure: FlaskClient, secure_app: Flask
) -> None:
    login(secure, Mode.SECURE, "jsmith")
    response = _transfer(secure, 1001, 7777, "10.00")
    assert response.status_code == 400
    assert balance(secure_app, 1001) == 150_000  # debit was rolled back


def test_vulnerable_bad_amount_leaks_stack_trace(vuln: FlaskClient) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    response = _transfer(vuln, 1001, 1002, "abc")
    assert response.status_code == 500
    assert "Traceback" in response.get_data(as_text=True)


def test_secure_schema_has_balance_floor_vulnerable_does_not() -> None:
    """A04: the secure schema enforces a non-negative balance; vulnerable has none."""
    assert "CHECK (balance_cents >= 0)" in schema_for(Mode.SECURE)
    assert "CHECK" not in schema_for(Mode.VULNERABLE)


def test_secure_bad_amount_returns_friendly_error(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    response = _transfer(secure, 1001, 1002, "abc")
    body = response.get_data(as_text=True)
    assert response.status_code == 400
    assert "Traceback" not in body
    assert "not a valid number" in body


@pytest.mark.parametrize(
    "raw", ["", "abc", "NaN", "Infinity", "1e30", "1.234", "0", "-1"]
)
def test_parse_amount_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValidationError):
        parse_amount_cents(raw)


@pytest.mark.parametrize(("raw", "cents"), [("1", 100), ("12.50", 1250), (" 0.01 ", 1)])
def test_parse_amount_accepts_valid_values(raw: str, cents: int) -> None:
    assert parse_amount_cents(raw) == cents


def test_parse_amount_enforces_upper_limit() -> None:
    assert parse_amount_cents("10000.00") == MAX_TRANSFER_CENTS
    with pytest.raises(ValidationError):
        parse_amount_cents("10000.01")
