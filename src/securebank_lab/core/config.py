"""Application settings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Mode(str, Enum):
    """Which implementation of the bank is served."""

    VULNERABLE = "vulnerable"
    SECURE = "secure"


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime configuration.

    Attributes:
        mode: Which implementation to serve.
        database_path: SQLite file. Defaults to one file per mode so that
            plaintext (vulnerable) and hashed (secure) data never mix.
        secret_key: Session signing key. Secure mode generates a random key
            when omitted; vulnerable mode deliberately uses a weak constant.
        cookie_secure: Set True when served over HTTPS so the session cookie
            gets the ``Secure`` flag and HSTS is sent.
    """

    mode: Mode = Mode.SECURE
    database_path: Path | None = None
    secret_key: str | None = None
    cookie_secure: bool = False

    @property
    def resolved_database_path(self) -> Path:
        """Return the configured path or the per-mode default under ``data/``."""
        return self.database_path or Path("data") / f"securebank_{self.mode.value}.db"
