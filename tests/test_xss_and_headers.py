"""XSS output encoding, CSRF, cookie flags and security headers."""

from __future__ import annotations

from flask.testing import FlaskClient

from securebank_lab.core.config import Mode
from tests.conftest import login

PAYLOAD = "<script>alert(1)</script>"


def test_vulnerable_search_reflects_script_unescaped(vuln: FlaskClient) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    body = vuln.get("/search", query_string={"q": PAYLOAD}).get_data(as_text=True)
    assert PAYLOAD in body


def test_secure_search_escapes_script(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    body = secure.get("/search", query_string={"q": PAYLOAD}).get_data(as_text=True)
    assert PAYLOAD not in body
    assert "&lt;script&gt;" in body


def test_secure_sends_hardening_headers(secure: FlaskClient) -> None:
    headers = secure.get("/login").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_vulnerable_sends_no_hardening_headers(vuln: FlaskClient) -> None:
    headers = vuln.get("/login").headers
    assert "Content-Security-Policy" not in headers
    assert "X-Content-Type-Options" not in headers


def test_secure_session_cookie_is_httponly_and_samesite(secure: FlaskClient) -> None:
    cookie = login(secure, Mode.SECURE, "jsmith").headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_vulnerable_session_cookie_lacks_httponly(vuln: FlaskClient) -> None:
    cookie = login(vuln, Mode.VULNERABLE, "jsmith").headers["Set-Cookie"]
    assert "HttpOnly" not in cookie


def test_secure_rejects_post_without_csrf_token(secure: FlaskClient) -> None:
    response = secure.post("/login", data={"username": "jsmith", "password": "x"})
    assert response.status_code == 403
