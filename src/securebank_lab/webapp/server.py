"""Loopback-restricted dev server for the lab.

Safety invariants:

* The bind address must be a loopback address. Vulnerable mode *refuses*
  to start on any other address, so the flawed implementation can never be
  exposed to a network by accident.
* The server banner hides version information (defence in depth for the
  Security Misconfiguration exercise).
"""

from __future__ import annotations

import sys

from securebank_lab.core.config import Settings
from securebank_lab.core.netutil import is_loopback
from securebank_lab.webapp.app import create_app


class QuietBannerHandler:
    """Minimal request handler whose banner hides version information."""

    def version_string(self) -> str:
        """Return a version-less banner."""
        return "SecureBank"


def serve_app(settings: Settings, host: str = "127.0.0.1", port: int = 5000) -> int:
    """Start the lab web server on a loopback address.

    Returns an exit code: 0 on graceful shutdown, 2 when the bind address
    is refused.
    """
    if not is_loopback(host):
        print(
            f"Refusing to bind to {host!r}: the lab may only be served on a "
            "loopback address (127.0.0.1, ::1, localhost).",
            file=sys.stderr,
        )
        return 2

    app = create_app(settings)
    debug = False  # the debugger must always stay off
    print(
        f"SecureBank Lab ({settings.mode.value}) listening on "
        f"http://{host}:{port} (loopback only)"
    )
    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\nServer stopped.")
    return 0


__all__ = ["QuietBannerHandler", "serve_app"]
