"""HTTP routes (thin: parse input, call the service, render a template)."""

from __future__ import annotations

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue

from securebank_lab.banking import AccountService, build_service
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
