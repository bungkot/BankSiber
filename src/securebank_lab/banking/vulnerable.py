"""INTENTIONALLY VULNERABLE implementation. For local teaching use only.

Each method contains exactly one documented flaw so students can find, exploit
and then fix it. The secure counterpart lives in ``secure.py``.
"""

from __future__ import annotations

import sqlite3

from securebank_lab.banking.base import list_accounts_for, to_transactions
from securebank_lab.core.models import Account, Transaction, User


class VulnerableAccountService:
    """Bank logic with deliberate OWASP-style weaknesses."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def authenticate(self, username: str, password: str) -> User | None:
        """VULN A05 Injection + A04 Cryptographic Failures + A07 Auth Failures.

        * SQL is built by string formatting, so input becomes SQL code.
        * Passwords are stored and compared in plaintext.
        * No rate limiting or lockout.
        """
        query = (
            "SELECT id, username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = self._conn.execute(query).fetchone()
        return None if row is None else User(row["id"], row["username"], row["role"])

    def list_accounts(self, requester: User) -> list[Account]:
        """List accounts (implemented correctly; the flaws are elsewhere)."""
        return list_accounts_for(self._conn, requester)

    def get_transactions(self, requester: User, account_id: int) -> list[Transaction]:
        """VULN A01 Broken Access Control (IDOR).

        The query is parameterised, but ``requester`` is never compared with the
        account owner, so any logged-in user can read any account.
        """
        rows = self._conn.execute(
            "SELECT id, account_id, description, amount_cents "
            "FROM transactions WHERE account_id = ? ORDER BY id",
            (account_id,),
        ).fetchall()
        return to_transactions(rows)

    def search_transactions(self, requester: User, term: str) -> list[Transaction]:
        """VULN A05 Injection: the search term is concatenated into the SQL."""
        query = (
            "SELECT t.id, t.account_id, t.description, t.amount_cents "
            "FROM transactions t JOIN accounts a ON a.id = t.account_id "
            f"WHERE a.owner_id = {requester.id} "
            f"AND t.description LIKE '%{term}%'"
        )
        return to_transactions(self._conn.execute(query).fetchall())

    def transfer(
        self, requester: User, from_account: int, to_account: int, amount: str
    ) -> None:
        """VULN A06 Insecure Design + A10 Mishandling of Exceptional Conditions.

        * ``float`` arithmetic for money (rounding errors).
        * Negative amounts are accepted, which reverses the direction.
        * Source-account ownership and balance are never checked.
        * Bad input raises an unhandled ``ValueError``.
        """
        cents = int(float(amount) * 100)
        with self._conn:
            self._conn.execute(
                "UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?",
                (cents, from_account),
            )
            self._conn.execute(
                "UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?",
                (cents, to_account),
            )
            self._conn.executemany(
                "INSERT INTO transactions (account_id, description, amount_cents) "
                "VALUES (?, ?, ?)",
                [
                    (from_account, f"Transfer to {to_account}", -cents),
                    (to_account, f"Transfer from {from_account}", cents),
                ],
            )
