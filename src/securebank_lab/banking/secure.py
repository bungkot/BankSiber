"""Hardened implementation: the fixed version of every flaw in vulnerable.py."""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from decimal import Decimal, InvalidOperation

from werkzeug.security import check_password_hash, generate_password_hash

from securebank_lab.banking.base import list_accounts_for, to_transactions
from securebank_lab.core.exceptions import (
    AccountLockedError,
    NotFoundError,
    ValidationError,
)
from securebank_lab.core.models import Account, Transaction, User

audit_log = logging.getLogger("securebank.audit")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
MAX_TRANSFER_CENTS = 1_000_000  # business limit: 10,000.00 per transfer
MAX_SEARCH_LENGTH = 100

# Verified against when the username is unknown, so response time does not
# reveal whether an account exists (user enumeration).
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def parse_amount_cents(raw: str) -> int:
    """Convert a decimal string to positive integer cents, or raise.

    Rejects non-numeric input, NaN/Infinity, more than two decimals, zero or
    negative values and anything above :data:`MAX_TRANSFER_CENTS`.
    """
    try:
        amount = Decimal(raw.strip())
        if not amount.is_finite() or amount != amount.quantize(Decimal("0.01")):
            raise ValidationError("Amount must have at most two decimal places.")
        cents = int(amount * 100)
    except (InvalidOperation, AttributeError, ValueError) as exc:
        raise ValidationError("Amount is not a valid number.") from exc
    if cents <= 0:
        raise ValidationError("Amount must be greater than zero.")
    if cents > MAX_TRANSFER_CENTS:
        raise ValidationError("Amount exceeds the per-transfer limit.")
    return cents


class SecureAccountService:
    """Bank logic applying input validation, least privilege and fail-secure."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._conn = conn
        self._clock = clock

    def authenticate(self, username: str, password: str) -> User | None:
        """Parameterised lookup, hashed passwords, progressive lockout, audit log."""
        now = self._clock()
        row = self._conn.execute(
            "SELECT id, username, password, role, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None:
            check_password_hash(_DUMMY_HASH, password)
            audit_log.warning("login_failed unknown_user=%r", username[:64])
            return None
        if row["locked_until"] > now:
            audit_log.warning("login_blocked user_id=%d (locked)", row["id"])
            raise AccountLockedError

        if check_password_hash(row["password"], password):
            with self._conn:
                self._conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = 0 "
                    "WHERE id = ?",
                    (row["id"],),
                )
            audit_log.info("login_ok user_id=%d", row["id"])
            return User(row["id"], row["username"], row["role"])

        attempts = row["failed_attempts"] + 1
        locked_until = 0.0
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until, attempts = now + LOCKOUT_SECONDS, 0
            audit_log.error("account_locked user_id=%d", row["id"])
        with self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, row["id"]),
            )
        audit_log.warning("login_failed user_id=%d", row["id"])
        return None

    def list_accounts(self, requester: User) -> list[Account]:
        """List only the requester's accounts."""
        return list_accounts_for(self._conn, requester)

    def get_transactions(self, requester: User, account_id: int) -> list[Transaction]:
        """Object-level authorisation; unknown and foreign accounts look the same."""
        owned = self._conn.execute(
            "SELECT 1 FROM accounts WHERE id = ? AND owner_id = ?",
            (account_id, requester.id),
        ).fetchone()
        if owned is None:
            audit_log.warning(
                "access_denied user_id=%d account_id=%d", requester.id, account_id
            )
            raise NotFoundError("Account not found.")
        rows = self._conn.execute(
            "SELECT id, account_id, description, amount_cents "
            "FROM transactions WHERE account_id = ? ORDER BY id",
            (account_id,),
        ).fetchall()
        return to_transactions(rows)

    def search_transactions(self, requester: User, term: str) -> list[Transaction]:
        """Bound parameters plus LIKE-wildcard escaping and a length limit."""
        if len(term) > MAX_SEARCH_LENGTH:
            raise ValidationError("Search term is too long.")
        escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self._conn.execute(
            "SELECT t.id, t.account_id, t.description, t.amount_cents "
            "FROM transactions t JOIN accounts a ON a.id = t.account_id "
            "WHERE a.owner_id = ? AND t.description LIKE ? ESCAPE '\\' "
            "ORDER BY t.id",
            (requester.id, f"%{escaped}%"),
        ).fetchall()
        return to_transactions(rows)

    def transfer(
        self, requester: User, from_account: int, to_account: int, amount: str
    ) -> None:
        """Validated, authorised, atomic transfer that fails closed."""
        cents = parse_amount_cents(amount)
        if from_account == to_account:
            raise ValidationError("Source and destination must differ.")
        with self._conn:  # one transaction: any exception rolls everything back
            debit = self._conn.execute(
                "UPDATE accounts SET balance_cents = balance_cents - ? "
                "WHERE id = ? AND owner_id = ? AND balance_cents >= ?",
                (cents, from_account, requester.id, cents),
            )
            if debit.rowcount == 0:
                owned = self._conn.execute(
                    "SELECT 1 FROM accounts WHERE id = ? AND owner_id = ?",
                    (from_account, requester.id),
                ).fetchone()
                if owned is None:
                    audit_log.warning(
                        "transfer_denied user_id=%d account_id=%d",
                        requester.id,
                        from_account,
                    )
                    raise NotFoundError("Account not found.")
                audit_log.warning(
                    "transfer_rejected user_id=%d account_id=%d (insufficient funds)",
                    requester.id,
                    from_account,
                )
                raise ValidationError("Insufficient funds.")
            credit = self._conn.execute(
                "UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?",
                (cents, to_account),
            )
            if credit.rowcount == 0:
                audit_log.warning(
                    "transfer_rejected user_id=%d account_id=%d (destination unknown)",
                    requester.id,
                    to_account,
                )
                raise ValidationError("Destination account not found.")
            self._conn.executemany(
                "INSERT INTO transactions (account_id, description, amount_cents) "
                "VALUES (?, ?, ?)",
                [
                    (from_account, f"Transfer to {to_account}", -cents),
                    (to_account, f"Transfer from {from_account}", cents),
                ],
            )
        audit_log.info(
            "transfer_ok user_id=%d from=%d to=%d cents=%d",
            requester.id,
            from_account,
            to_account,
            cents,
        )
