"""A08: ledger export integrity — unkeyed MD5 (vulnerable) vs keyed HMAC (secure)."""

from __future__ import annotations

import hashlib
import hmac

from flask.testing import FlaskClient

from securebank_lab.banking.integrity import HmacIntegrityStamper
from tests.conftest import login


def _export(client: FlaskClient, mode: str, password: str) -> tuple[str, str]:
    """Log in as jsmith and return (body, X-Integrity header)."""
    login(client, mode, "jsmith", password)  # type: ignore[arg-type]
    response = client.get("/accounts/ledger/export")
    assert response.status_code == 200
    return response.get_data(as_text=True), response.headers["X-Integrity"]


def test_vulnerable_export_stamp_is_forgable_md5(vuln: FlaskClient) -> None:
    body, header = _export(vuln, "vulnerable", "demo1234")
    assert header.startswith("MD5 ")
    recomputed = hashlib.md5(body.encode()).hexdigest()  # noqa: S324 - proves the flaw
    assert header.split(" ", 1)[1] == recomputed


def test_secure_export_stamp_is_keyed_hmac(secure: FlaskClient) -> None:
    body, header = _export(secure, "secure", "Cx7!mango-orbit")
    assert header.startswith("HMAC-SHA256 ")
    stamp = header.split(" ", 1)[1]
    recomputed_md5 = hashlib.md5(body.encode()).hexdigest()  # noqa: S324 - proves the fix
    assert stamp != recomputed_md5
    expected = HmacIntegrityStamper(b"test-only-key").stamp(body.encode())
    assert hmac.compare_digest(stamp, expected)


def test_export_is_owner_scoped(secure: FlaskClient) -> None:
    body, _ = _export(secure, "secure", "Cx7!mango-orbit")
    # jsmith owns accounts 1001 only; the admin's 1003 must not appear.
    assert "1003" not in body.split("\n", 1)[1]  # header line excluded
