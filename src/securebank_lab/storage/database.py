"""SQLite access, schema and demo data."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from flask import current_app, g
from werkzeug.security import generate_password_hash

from securebank_lab.core.config import Mode, Settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    password        TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL    NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0 OR :allow_negative)
);
CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id),
    description  TEXT    NOT NULL,
    amount_cents INTEGER NOT NULL
);
"""

# Lab-only demo credentials. The vulnerable set mirrors the "default
# credentials" finding (A07); the secure set is still public (it is in the
# README) and must never be reused anywhere real.
DEMO_CREDENTIALS: dict[Mode, dict[str, str]] = {
    Mode.VULNERABLE: {
        "jsmith": "demo1234",
        "admin": "admin",
        "sgreen": "password1",
    },
    Mode.SECURE: {
        "jsmith": "Cx7!mango-orbit",
        "admin": "Qz4#delta-ridge-91",
        "sgreen": "Lm9$plum-harbor",
    },
}

_USERS = (("jsmith", "customer", 1), ("admin", "admin", 2), ("sgreen", "customer", 3))
_ACCOUNTS = ((1001, 1, 150_000), (1002, 3, 500_000), (1003, 2, 9_000_000))
_TRANSACTIONS = (
    (1001, "Salary March", 300_000),
    (1001, "Rent", -150_000),
    (1002, "Invoice 2026-114", 520_000),
    (1002, "Confidential: tax payment", -20_000),
    (1003, "Treasury top-up", 9_000_000),
)


def connect(path: Path | str) -> sqlite3.Connection:
    """Open a connection with row access by name and foreign keys enforced."""
    parent = Path(path).parent
    if str(parent):
        parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: Path | str, mode: Mode) -> None:
    """Create the schema and seed demo data if the database is empty."""
    with closing(connect(path)) as conn:
        # The vulnerable bank has no balance constraint (A06 Insecure Design).
        schema = SCHEMA.replace(
            ":allow_negative", "1" if mode is Mode.VULNERABLE else "0"
        )
        conn.executescript(schema)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        passwords = DEMO_CREDENTIALS[mode]
        for username, role, user_id in _USERS:
            stored = passwords[username]
            if mode is Mode.SECURE:
                stored = generate_password_hash(stored)  # salted, slow hash
            conn.execute(
                "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
                (user_id, username, stored, role),
            )
        conn.executemany(
            "INSERT INTO accounts (id, owner_id, balance_cents) VALUES (?, ?, ?)",
            _ACCOUNTS,
        )
        conn.executemany(
            "INSERT INTO transactions (account_id, description, amount_cents) "
            "VALUES (?, ?, ?)",
            _TRANSACTIONS,
        )
        conn.commit()


def get_db() -> sqlite3.Connection:
    """Return the per-request connection, opening it on first use."""
    if "db" not in g:
        settings: Settings = current_app.config["SETTINGS"]
        g.db = connect(settings.resolved_database_path)
    conn: sqlite3.Connection = g.db
    return conn


def close_db(_exc: BaseException | None = None) -> None:
    """Close the per-request connection (registered as a teardown hook)."""
    conn: sqlite3.Connection | None = g.pop("db", None)
    if conn is not None:
        conn.close()
