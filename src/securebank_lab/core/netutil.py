"""Small networking helpers shared by the server and the pentest tool."""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from email.message import Message
from typing import IO


def is_loopback(host: str) -> bool:
    """Return True if ``host`` refers only to this machine.

    Literal IP addresses are checked directly. A name is *resolved* first and
    every resolved address must be loopback, so a name such as
    ``"localhost"`` cannot silently map to an external address (DNS
    rebinding). An unresolvable name fails closed.
    """
    if not host:
        return False
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        pass  # not a literal address; resolve it below
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    return bool(infos) and all(
        ipaddress.ip_address(info[4][0]).is_loopback for info in infos
    )


class HTTPRedirectGuard(urllib.request.HTTPRedirectHandler):
    """Urllib handler that surfaces 3xx responses instead of following them.

    Used wherever a fetcher must not let a trusted origin redirect it to
    another destination (the pentest client wants to *see* redirects; the
    allowlisted statement importer must *refuse* them).
    """

    def redirect_request(  # noqa: PLR0913, PLR0917 - signature fixed by urllib's API
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None
