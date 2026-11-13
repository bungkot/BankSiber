"""Flask application factory."""

from __future__ import annotations

import logging
import secrets
import traceback
import uuid
from typing import Any

from flask import Flask, Response, render_template, request
from flask.typing import ResponseReturnValue
from markupsafe import Markup
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers import Response as WerkzeugResponse

from securebank_lab.core.config import Mode, Settings
from securebank_lab.core.models import format_cents
from securebank_lab.storage.database import close_db, init_db
from securebank_lab.webapp.routes import bp
from securebank_lab.webapp.security import (
    add_security_headers,
    csrf_field,
    enforce_csrf,
)

logger = logging.getLogger(__name__)

# VULN A02 Security Misconfiguration: a guessable signing key lets anyone
# forge session cookies. Used only in vulnerable mode.
_WEAK_SECRET = "secret"  # noqa: S105


def create_app(settings: Settings | None = None) -> Flask:
    """Build and configure the application for the requested mode."""
    settings = settings or Settings()
    secure = settings.mode is Mode.SECURE

    app = Flask(__name__)
    app.config.update(
        SETTINGS=settings,
        SECRET_KEY=settings.secret_key
        or (secrets.token_hex(32) if secure else _WEAK_SECRET),
        SESSION_COOKIE_HTTPONLY=secure,
        SESSION_COOKIE_SAMESITE="Lax" if secure else None,
        SESSION_COOKIE_SECURE=secure and settings.cookie_secure,
        MAX_CONTENT_LENGTH=64 * 1024 if secure else None,
    )
    init_db(settings.resolved_database_path, settings.mode)

    app.jinja_env.filters["money"] = format_cents
    app.teardown_appcontext(close_db)
    app.register_blueprint(bp)

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "mode": settings.mode.value,
            "csrf_field": csrf_field if secure else (lambda: Markup("")),
        }

    if secure:
        app.before_request(enforce_csrf)

        @app.after_request
        def harden(response: WerkzeugResponse) -> WerkzeugResponse:
            return add_security_headers(response, hsts=settings.cookie_secure)

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception) -> ResponseReturnValue:
        if isinstance(exc, HTTPException):
            return exc.get_response()
        if secure:
            # Fail secure: generic message to the user, details only in the log.
            error_id = uuid.uuid4().hex[:12]
            logger.error(
                "unhandled_error id=%s path=%s", error_id, request.path, exc_info=exc
            )
            return render_template("error.html", error_id=error_id), 500
        # VULN A10: the full stack trace is sent to the client.
        trace = "".join(traceback.format_exception(exc))
        return Response(trace, status=500, mimetype="text/plain")

    return app
