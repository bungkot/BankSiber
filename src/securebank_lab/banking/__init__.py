"""Banking domain layer: one interface, two implementations.

* :class:`securebank_lab.banking.vulnerable.VulnerableAccountService` -
  deliberately flawed, for attack research.
* :class:`securebank_lab.banking.secure.SecureAccountService` - the hardened
  counterpart that fixes every documented flaw.
"""

from __future__ import annotations

import sqlite3

from securebank_lab.banking.base import AccountService
from securebank_lab.banking.secure import SecureAccountService
from securebank_lab.banking.vulnerable import VulnerableAccountService
from securebank_lab.core.config import Mode

__all__ = [
    "AccountService",
    "SecureAccountService",
    "VulnerableAccountService",
    "build_service",
]


def build_service(conn: sqlite3.Connection, mode: Mode) -> AccountService:
    """Return the service implementation matching ``mode``."""
    if mode is Mode.SECURE:
        return SecureAccountService(conn)
    return VulnerableAccountService(conn)
