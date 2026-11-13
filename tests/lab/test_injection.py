"""A05 Injection: SQL injection in login and search."""

from __future__ import annotations

from flask.testing import FlaskClient

from securebank_lab.core.config import Mode
from tests.conftest import login


def test_vulnerable_login_bypassed_with_sql_comment(vuln: FlaskClient) -> None:
    response = login(vuln, Mode.VULNERABLE, "admin'--", "wrong")
    assert response.status_code == 302
    assert "admin" in vuln.get("/").get_data(as_text=True)


def test_secure_login_rejects_sql_comment_payload(secure: FlaskClient) -> None:
    response = login(secure, Mode.SECURE, "admin'--", "wrong")
    assert response.status_code == 401


def test_vulnerable_login_leaks_sql_error_on_order_by_probe(vuln: FlaskClient) -> None:
    response = login(vuln, Mode.VULNERABLE, "x' ORDER BY 99--", "x")
    body = response.get_data(as_text=True)
    assert response.status_code == 500
    assert "OperationalError" in body  # same signal the pentest report used


def test_secure_login_treats_probe_as_plain_text(secure: FlaskClient) -> None:
    response = login(secure, Mode.SECURE, "x' ORDER BY 99--", "x")
    body = response.get_data(as_text=True)
    assert response.status_code == 401
    assert "OperationalError" not in body


def test_vulnerable_search_allows_union_injection(vuln: FlaskClient) -> None:
    login(vuln, Mode.VULNERABLE, "jsmith")
    payload = "zzz' UNION SELECT id, id, username || ':' || password, 0 FROM users--"
    body = vuln.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert "admin:admin" in body  # data from another table leaks


def test_secure_search_blocks_union_injection(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    payload = "zzz' UNION SELECT id, id, username || ':' || password, 0 FROM users--"
    body = secure.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert "admin:" not in body
    assert "No matches" in body


def test_secure_search_escapes_like_wildcards(secure: FlaskClient) -> None:
    login(secure, Mode.SECURE, "jsmith")
    body = secure.get("/search", query_string={"q": "%"}).get_data(as_text=True)
    assert "No matches" in body  # '%' is literal, not "match everything"
