"""The contract both implementations satisfy, plus shared helpers."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from securebank_lab.core.models import Account, Transaction, User


class AccountService(Protocol):
    """Business operations of the bank."""

    def authenticate(self, username: str, password: str) -> User | None:
        """Return the user for valid credentials, otherwise ``None``."""

    def list_accounts(self, requester: User) -> list[Account]:
        """Return the accounts owned by ``requester``."""

    def get_transactions(self, requester: User, account_id: int) -> list[Transaction]:
        """Return the ledger of one account."""

    def search_transactions(self, requester: User, term: str) -> list[Transaction]:
        """Search the requester's own transactions by description."""

    def transfer(
        self, requester: User, from_account: int, to_account: int, amount: str
    ) -> None:
        """Move ``amount`` (a decimal string such as ``"12.50"``) between accounts."""


def list_accounts_for(conn: sqlite3.Connection, requester: User) -> list[Account]:
    """Parameterised, owner-scoped account listing (correct in both modes)."""
    rows = conn.execute(
        "SELECT id, owner_id, balance_cents FROM accounts WHERE owner_id = ? "
        "ORDER BY id",
        (requester.id,),
    ).fetchall()
    return [Account(r["id"], r["owner_id"], r["balance_cents"]) for r in rows]


def to_transactions(rows: list[sqlite3.Row]) -> list[Transaction]:
    """Map database rows to :class:`Transaction` objects."""
    return [
        Transaction(r["id"], r["account_id"], r["description"], r["amount_cents"])
        for r in rows
    ]
