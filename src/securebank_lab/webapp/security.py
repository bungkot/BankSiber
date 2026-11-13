"""HTTP-level protections used by the secure mode: CSRF, headers, auth guard."""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from flask import abort, redirect, request, session, url_for
from flask.typing import ResponseReturnValue
from markupsafe import Markup
from werkzeug.wrappers import Response

from securebank_lab.core.models import User

F = TypeVar("F", bound=Callable[..., Any])

_CSRF_KEY = "csrf_token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; "
        "base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def get_csrf_token() -> str:
    """Return the session's CSRF token, creating it on first use."""
    if _CSRF_KEY not in session:
        session[_CSRF_KEY] = secrets.token_urlsafe(32)
    return str(session[_CSRF_KEY])


def csrf_field() -> Markup:
    """Render the hidden CSRF input for forms (secure mode only)."""
    # Markup.format() HTML-escapes its arguments, unlike an f-string.
    return Markup('<input type="hidden" name="csrf_token" value="{}">').format(
        get_csrf_token()
    )


def enforce_csrf() -> None:
    """Abort with 403 unless a state-changing request carries a valid token."""
    if request.method in _SAFE_METHODS:
        return
    expected = str(session.get(_CSRF_KEY, ""))
    supplied = request.form.get(_CSRF_KEY, "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(403)


def add_security_headers(response: Response, *, hsts: bool) -> Response:
    """Attach the hardening headers to every response."""
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    if hsts:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def current_user() -> User | None:
    """Return the logged-in user stored in the session, if any."""
    data = session.get("user")
    if not isinstance(data, dict):
        return None
    try:
        return User(
            id=int(data["id"]), username=str(data["username"]), role=str(data["role"])
        )
    except (KeyError, TypeError, ValueError):
        return None


def login_required(view: F) -> F:
    """Redirect anonymous visitors to the login page."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> ResponseReturnValue:
        if current_user() is None:
            return redirect(url_for("bank.login_form"))
        return cast(ResponseReturnValue, view(*args, **kwargs))

    return cast(F, wrapped)
