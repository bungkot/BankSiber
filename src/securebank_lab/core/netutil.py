"""Small networking helpers shared by the server and the pentest tool."""

from __future__ import annotations

import ipaddress


def is_loopback(host: str) -> bool:
    """Return True if ``host`` refers only to this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
