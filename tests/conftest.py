"""Shared fixtures and helpers."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from securebank_lab.core.config import Mode, Settings
from securebank_lab.storage.database import DEMO_CREDENTIALS, connect
from securebank_lab.webapp.app import create_app

AppFactory = Callable[[Mode], Flask]

_TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def make_app(tmp_path: Path) -> AppFactory:
    """Return a factory that builds an isolated app (own database) per mode."""

    def _make(mode: Mode) -> Flask:
        settings = Settings(
            mode=mode,
            database_path=tmp_path / f"{mode.value}.db",
            secret_key="test-only-key",
        )
        return create_app(settings)

    return _make


@pytest.fixture
def vuln_app(make_app: AppFactory) -> Flask:
    """An app running the intentionally vulnerable implementation."""
    return make_app(Mode.VULNERABLE)


@pytest.fixture
def secure_app(make_app: AppFactory) -> Flask:
    """An app running the hardened implementation."""
    return make_app(Mode.SECURE)


@pytest.fixture
def vuln(vuln_app: Flask) -> FlaskClient:
    """Test client for the vulnerable app."""
    return vuln_app.test_client()


@pytest.fixture
def secure(secure_app: Flask) -> FlaskClient:
    """Test client for the secure app."""
    return secure_app.test_client()


def csrf_token(client: FlaskClient) -> str:
    """Fetch the CSRF token (empty string in vulnerable mode, which has none)."""
    html = client.get("/login").get_data(as_text=True)
    match = _TOKEN_RE.search(html)
    return match.group(1) if match else ""


def post(client: FlaskClient, url: str, data: dict[str, str]) -> TestResponse:
    """POST a form, adding the CSRF token when the app uses one."""
    return client.post(url, data={**data, "csrf_token": csrf_token(client)})


def login(
    client: FlaskClient, mode: Mode, username: str, password: str | None = None
) -> TestResponse:
    """Log in; defaults to the demo password of ``mode``."""
    secret = password if password is not None else DEMO_CREDENTIALS[mode][username]
    return post(client, "/login", {"username": username, "password": secret})


def balance(app: Flask, account_id: int) -> int:
    """Read an account balance straight from the database."""
    settings: Settings = app.config["SETTINGS"]
    conn = connect(settings.resolved_database_path)
    try:
        row: sqlite3.Row = conn.execute(
            "SELECT balance_cents FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        return int(row["balance_cents"])
    finally:
        conn.close()
