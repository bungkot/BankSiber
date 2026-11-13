"""A06: component exposure — version disclosure (vulnerable) vs minimal (secure)."""

from __future__ import annotations

import json

from flask.testing import FlaskClient


def test_vulnerable_about_discloses_versions(vuln: FlaskClient) -> None:
    response = vuln.get("/about")
    assert response.status_code == 200
    data = json.loads(response.get_data(as_text=True))
    assert data["components"]["flask"]
    assert data["components"]["werkzeug"]
    assert "eol" in data["components"]["payments-core"].lower()


def test_secure_about_discloses_nothing(secure: FlaskClient) -> None:
    response = secure.get("/about")
    assert response.status_code == 200
    data = json.loads(response.get_data(as_text=True))
    assert "components" not in data
    assert "flask" not in response.get_data(as_text=True)
