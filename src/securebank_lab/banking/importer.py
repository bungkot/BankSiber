"""External statement import feature (OWASP A10 SSRF demonstration).

* :class:`VulnerableStatementImporter` - INTENTIONALLY VULNERABLE: fetches
  whatever URL the client supplies, with any scheme (``file://`` included),
  so the server can be tricked into reading internal resources.
* :class:`SecureStatementImporter` - the fix: scheme + host allowlist,
  response-size cap and short timeout; everything else fails closed.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from typing import Protocol

from securebank_lab.core.config import Mode
from securebank_lab.core.exceptions import ValidationError

_MAX_RESPONSE_BYTES = 64_000
_TIMEOUT_SECONDS = 5.0

# Only this fictional provider is allowed to serve statements in secure mode.
# Nothing in the lab resolves it: the allowlist exists to deny everything else.
_ALLOWED_HOSTS = frozenset({"statements.lab.internal"})


class StatementImporter(Protocol):
    """Fetches a CSV statement from a configured source URL."""

    def fetch(self, url: str) -> str:
        """Return the statement text, or raise :class:`ValidationError`."""


class VulnerableStatementImporter:
    """VULN A10 SSRF: no scheme, host or redirect validation."""

    def fetch(self, url: str) -> str:
        """Fetch ``url`` blindly - internal and file resources are reachable."""
        try:
            # VULN: user-controlled URL handed to urlopen (file://, internal
            # http://... all allowed). Size cap only, no allowlist.
            with urllib.request.urlopen(  # noqa: S310 - the flaw under study
                url, timeout=_TIMEOUT_SECONDS
            ) as response:
                raw: bytes = response.read(_MAX_RESPONSE_BYTES)
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ValidationError(f"Could not fetch statement: {exc}") from exc


class SecureStatementImporter:
    """Allowlisted fetch: https only, trusted provider hosts only."""

    def fetch(self, url: str) -> str:
        """Fetch ``url`` only if scheme and host are on the allowlist."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise ValidationError("Statement source must use https.")
        if parsed.hostname not in _ALLOWED_HOSTS:
            raise ValidationError("Statement source host is not allowlisted.")
        try:
            with urllib.request.urlopen(  # noqa: S310 - allowlisted https only
                url, timeout=_TIMEOUT_SECONDS
            ) as response:
                raw: bytes = response.read(_MAX_RESPONSE_BYTES)
                return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ValidationError(f"Could not fetch statement: {exc}") from exc


def build_importer(mode: Mode) -> StatementImporter:
    """Return the importer matching ``mode``."""
    if mode is Mode.SECURE:
        return SecureStatementImporter()
    return VulnerableStatementImporter()
