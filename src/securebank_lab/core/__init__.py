"""Core kernel: configuration, domain models, exceptions and shared helpers.

Everything in :mod:`securebank_lab` depends on this package; it depends on
nothing inside the project (no Flask, no services, no I/O framework).
"""

from __future__ import annotations

from securebank_lab.core.config import Mode, Settings
from securebank_lab.core.exceptions import (
    AccountLockedError,
    BankError,
    NotFoundError,
    ValidationError,
)
from securebank_lab.core.models import Account, Transaction, User, format_cents
from securebank_lab.core.netutil import is_loopback
from securebank_lab.core.version import __version__

__all__ = [
    "Account",
    "AccountLockedError",
    "BankError",
    "Mode",
    "NotFoundError",
    "Settings",
    "Transaction",
    "User",
    "ValidationError",
    "__version__",
    "format_cents",
    "is_loopback",
]
