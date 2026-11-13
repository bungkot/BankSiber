"""HTTP routes (thin: parse input, call the service, render a template)."""

from __future__ import annotations

import logging
from importlib.metadata import version as _pkg_version

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue

from securebank_lab.banking import AccountService, build_service
from securebank_lab.banking.importer import build_importer
from securebank_lab.banking.integrity import build_stamper, ledger_csv_for
from securebank_lab.core.config import Mode, Settings
from securebank_lab.core.exceptions import (
    AccountLockedError,
    NotFoundError,
    ValidationError,
)
from securebank_lab.core.models import User
from securebank_lab.storage.database import get_db
from securebank_lab.webapp.security import current_user, login_required

bp = Blueprint("bank", __name__)

audit_log = logging.getLogger("securebank.audit")

# Simulated third-party component used by the A06 exercise. It does not
# exist; it models "a pinned dependency that is past end of life".
_OUTDATED_COMPONENT = "payments-core 1.2.1-eol (unsupported since 2024)"

_GENERIC_LOGIN_ERROR = "Invalid credentials or account temporarily locked."


def _settings() -> Settings:
    settings: Settings = current_app.config["SETTINGS"]
    return settings


def _service() -> AccountService:
    return build_service(get_db(), _settings().mode)


def _user() -> User:
    user = current_user()
    if user is None:  # pragma: no cover - guarded by @login_required
        abort(401)
    return user


def _form_int(name: str) -> int:
    try:
        return int(request.form.get(name, ""))
    except ValueError as exc:
        raise ValidationError(f"{name} must be a whole number.") from exc


@bp.get("/login")
def login_form() -> ResponseReturnValue:
    """Show the login form."""
    return render_template("login.html")


@bp.post("/login")
def login() -> ResponseReturnValue:
    """Authenticate and start a session."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    try:
        user = _service().authenticate(username, password)
    except AccountLockedError:
        user = None
    if user is None:
        # One generic message for every failure: no user enumeration.
        return render_template("login.html", error=_GENERIC_LOGIN_ERROR), 401
    if _settings().mode is Mode.SECURE:
        session.clear()  # new session after login prevents session fixation
    session["user"] = {"id": user.id, "username": user.username, "role": user.role}
    return redirect(url_for("bank.dashboard"))


@bp.post("/logout")
def logout() -> ResponseReturnValue:
    """End the session."""
    session.clear()
    return redirect(url_for("bank.login_form"))


@bp.get("/")
@login_required
def dashboard() -> ResponseReturnValue:
    """List the user's accounts."""
    accounts = _service().list_accounts(_user())
    return render_template("dashboard.html", accounts=accounts)


@bp.get("/accounts/<int:account_id>/transactions")
@login_required
def transactions(account_id: int) -> ResponseReturnValue:
    """Show one account's ledger."""
    try:
        items = _service().get_transactions(_user(), account_id)
    except NotFoundError:
        abort(404)
    return render_template("transactions.html", account_id=account_id, items=items)


@bp.get("/search")
@login_required
def search() -> ResponseReturnValue:
    """Search the user's transactions."""
    term = request.args.get("q", "")
    items = []
    if term:
        try:
            items = _service().search_transactions(_user(), term)
        except ValidationError as exc:
            return render_template(
                "search.html", term="", items=[], error=str(exc)
            ), 400
    return render_template("search.html", term=term, items=items)


@bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer() -> ResponseReturnValue:
    """Show the transfer form or perform a transfer."""
    if request.method == "GET":
        return render_template("transfer.html")
    try:
        _service().transfer(
            _user(),
            _form_int("from_account"),
            _form_int("to_account"),
            request.form.get("amount", ""),
        )
    except ValidationError as exc:
        return render_template("transfer.html", error=str(exc)), 400
    except NotFoundError:
        abort(404)
    return redirect(url_for("bank.dashboard"))


@bp.get("/about")
def about() -> ResponseReturnValue:
    """Component information endpoint.

    VULN A06 in vulnerable mode: exact framework versions and a past-EOL
    dependency are disclosed to anonymous visitors (component
    reconnaissance for an attacker). Secure mode answers without any
    component detail.
    """
    if _settings().mode is Mode.SECURE:
        return jsonify({"status": "ok"})  # no component details
    return jsonify(
        {
            "application": "SecureBank Lab",
            "mode": "vulnerable",
            "components": {
                "flask": _pkg_version("flask"),
                "werkzeug": _pkg_version("werkzeug"),
                "payments-core": _OUTDATED_COMPONENT,
            },
        }
    )


@bp.get("/accounts/ledger/export")
@login_required
def ledger_export() -> ResponseReturnValue:
    """Export the requester's ledger with an integrity stamp (OWASP A08).

    VULN A08 in vulnerable mode: the stamp is unkeyed MD5 - anyone can
    recompute it after editing the file, so it proves nothing. Secure mode
    uses keyed HMAC-SHA256.
    """
    user = _user()
    data = ledger_csv_for(get_db(), user)
    stamper = build_stamper(_settings().mode, str(current_app.secret_key))
    if _settings().mode is Mode.SECURE:
        audit_log.info("ledger_exported user_id=%d bytes=%d", user.id, len(data))
    response = Response(data, mimetype="text/csv")
    response.headers["X-Integrity"] = f"{stamper.label()} {stamper.stamp(data)}"
    return response


@bp.get("/import/statement")
@login_required
def import_statement() -> ResponseReturnValue:
    """Fetch an external statement by URL (OWASP A10 SSRF in vulnerable mode).

    VULN A10 in vulnerable mode: the URL is fetched with no scheme or host
    validation, so ``file://`` and internal ``http://`` resources are
    readable. Secure mode fails closed on an https + host allowlist.
    """
    user = _user()
    url = request.args.get("url", "")
    preview: str | None = None
    error: str | None = None
    if url:
        try:
            preview = build_importer(_settings().mode).fetch(url)
        except ValidationError as exc:
            error = str(exc)
            if _settings().mode is Mode.SECURE:
                # A09 (secure): the denied attempt is recorded for monitoring.
                audit_log.warning(
                    "import_rejected user_id=%d url=%r", user.id, url[:128]
                )
    status = 400 if error else 200
    return (
        render_template("import.html", url=url, preview=preview, error=error),
        status,
    )
