"""Data-integrity primitives for the ledger export feature (OWASP A08).

* :class:`LegacyIntegrityStamper` - INTENTIONALLY WEAK: unkeyed MD5. Anyone
  can recompute it, so it proves nothing about who produced the data.
* :class:`HmacIntegrityStamper` - the fix: keyed HMAC-SHA256 with a server
  secret, so tampering is detectable.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from typing import Protocol

from securebank_lab.core.config import Mode
from securebank_lab.core.models import User

_VULN_LABEL = "MD5"


class IntegrityStamper(Protocol):
    """Computes a verifiable stamp over exported bytes."""

    def label(self) -> str:
        """Human-readable algorithm identifier used in the header."""

    def stamp(self, data: bytes) -> str:
        """Return the hex digest for ``data``."""


class LegacyIntegrityStamper:
    """VULN A06 + A08: unkeyed MD5 over the export.

    MD5 is a deprecated, collision-broken primitive, and because the stamp is
    unkeyed, *anyone* can recompute it after tampering with the data.
    """

    def label(self) -> str:
        """Return the weak algorithm label."""
        return _VULN_LABEL

    def stamp(self, data: bytes) -> str:
        """Return the plain MD5 hex digest (no secret involved)."""
        return hashlib.md5(data).hexdigest()  # noqa: S324 - documented lab flaw


class HmacIntegrityStamper:
    """Secure counterpart: keyed HMAC-SHA256 using the server secret."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def label(self) -> str:
        """Return the strong algorithm label."""
        return "HMAC-SHA256"

    def stamp(self, data: bytes) -> str:
        """Return the HMAC-SHA256 hex digest."""
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()


def build_stamper(mode: Mode, secret_key: str) -> IntegrityStamper:
    """Return the stamper matching ``mode``."""
    if mode is Mode.SECURE:
        return HmacIntegrityStamper(secret_key.encode())
    return LegacyIntegrityStamper()


def ledger_csv_for(conn: sqlite3.Connection, requester: User) -> bytes:
    """Build a CSV export of the requester's ledger (parameterised, owner-scoped)."""
    rows = conn.execute(
        "SELECT t.id, t.account_id, t.description, t.amount_cents "
        "FROM transactions t JOIN accounts a ON a.id = t.account_id "
        "WHERE a.owner_id = ? ORDER BY t.id",
        (requester.id,),
    ).fetchall()
    lines = ["id,account_id,description,amount_cents"]
    lines += [
        f'{r["id"]},{r["account_id"]},"{r["description"]}",{r["amount_cents"]}'
        for r in rows
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")
