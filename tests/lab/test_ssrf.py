"""A10: statement import — arbitrary fetch (vulnerable) vs allowlist (secure)."""

from __future__ import annotations

import io
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from securebank_lab.banking.importer import SecureStatementImporter
from securebank_lab.core.exceptions import ValidationError
from securebank_lab.core.netutil import HTTPRedirectGuard
from tests.conftest import login


def _login(client: FlaskClient, mode: str, password: str) -> None:
    login(client, mode, "jsmith", password)  # type: ignore[arg-type]


def test_vulnerable_importer_reads_local_files(
    vuln: FlaskClient, tmp_path: Path
) -> None:
    secret = tmp_path / "internal.txt"
    secret.write_text("INTERNAL-SECRET-MARKER", encoding="utf-8")
    _login(vuln, "vulnerable", "demo1234")
    response = vuln.get(f"/import/statement?url={secret.as_uri()}")
    assert response.status_code == 200
    assert "INTERNAL-SECRET-MARKER" in response.get_data(as_text=True)


def test_secure_importer_rejects_file_scheme(
    secure: FlaskClient, tmp_path: Path
) -> None:
    _login(secure, "secure", "Cx7!mango-orbit")
    response = secure.get(f"/import/statement?url={(tmp_path / 'x.txt').as_uri()}")
    assert response.status_code == 400


def test_secure_importer_rejects_internal_http(secure: FlaskClient) -> None:
    _login(secure, "secure", "Cx7!mango-orbit")
    response = secure.get("/import/statement?url=http://127.0.0.1:5000/login")
    assert response.status_code == 400
    assert "must use https" in response.get_data(as_text=True)


def test_secure_importer_allows_allowlisted_https(
    secure: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeResponse:
        def read(self, n: int) -> bytes:
            return b"csv,statement\n"

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class FakeOpener:
        def open(self, req: urllib.request.Request, timeout: float) -> FakeResponse:
            assert req.full_url.startswith("https://statements.lab.internal")
            return FakeResponse()

    importer = SecureStatementImporter()
    monkeypatch.setattr(importer, "_opener", FakeOpener())
    assert "csv,statement" in importer.fetch("https://statements.lab.internal/q.csv")


def test_secure_importer_opener_refuses_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 3xx from the allowlisted host must fail closed, never be followed."""
    importer = SecureStatementImporter()

    class RedirectingOpener:
        def open(self, req: urllib.request.Request, timeout: float) -> str:
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", Message(), io.BytesIO(b"")
            )

    monkeypatch.setattr(importer, "_opener", RedirectingOpener())
    with pytest.raises(ValidationError, match="Could not fetch statement"):
        importer.fetch("https://statements.lab.internal/q.csv")


def test_redirect_guard_never_returns_a_followup_request() -> None:
    """The guard itself: redirect_request must refuse every redirect."""
    handler = HTTPRedirectGuard()
    request = urllib.request.Request("https://statements.lab.internal/q.csv")
    assert (
        handler.redirect_request(request, io.BytesIO(b""), 302, "Found", Message(), "")
        is None
    )


def test_vulnerable_importer_reports_fetch_errors(vuln: FlaskClient) -> None:
    _login(vuln, "vulnerable", "demo1234")
    response = vuln.get("/import/statement?url=http://127.0.0.1:1/nope")
    assert response.status_code == 400  # error rendered on the page, not a 500
    assert "Could not fetch statement" in response.get_data(as_text=True)
    assert "Traceback" not in response.get_data(as_text=True)
