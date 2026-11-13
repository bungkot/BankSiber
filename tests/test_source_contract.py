"""Contract: tests must exercise functions that actually exist in ``src/``.

Every public callable (top-level function or class) defined by a
``securebank_lab`` module must be referenced by name in at least one test
file, or be listed in ``_EXCLUDED`` with a documented reason. This keeps the
suite honest: a test can never claim to verify something the source does not
provide, and source functions cannot drift into being never-tested.

Run it with the other suites: ``pytest tests/test_source_contract.py``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

_SRC = Path("src/securebank_lab")
_TESTS = Path("tests")

# Public callables that are not referenced by name in any test module.
# Every entry must state *why* the name is exercised indirectly instead.
_EXCLUDED: dict[str, str] = {
    # --- protocols and data containers -------------------------------------
    "banking.base:AccountService": "Protocol; both implementations are exercised through tests/lab.",
    "banking.importer:StatementImporter": "Protocol; both implementations exercised in tests/lab/test_ssrf.py.",
    "banking.integrity:IntegrityStamper": "Protocol; both implementations exercised in tests/lab/test_integrity.py.",
    "core.models:Account": "Dataclass exercised indirectly via service/API behaviour tests.",
    "core.models:Transaction": "Dataclass exercised indirectly via service/API behaviour tests.",
    "core.models:User": "Dataclass exercised indirectly via session behaviour tests.",
    "pentest.client:HttpResponse": "Dataclass returned by LabClient; asserted via its fields in tests/tool/test_pentest.py.",
    "pentest.models:Finding": "Dataclass asserted via fields in tests/tool/test_pentest.py.",
    "pentest.models:Outcome": "Dataclass asserted via fields in tests/tool/test_pentest.py.",
    "pentest.models:Severity": "Enum asserted via findings in tests/tool/test_pentest.py.",
    "pentest.models:Spec": "Dataclass asserted via CHECKS in tests/tool/test_pentest.py.",
    "pentest.report:Report": "Dataclass built by assess(); asserted via render helpers.",
    "research.analyzer:AttackSurface": "Dataclass returned by ResearchAnalyzer; asserted via fields in tests/tool/test_research.py.",
    "research.analyzer:ResearchReport": "Dataclass returned by ResearchAnalyzer; asserted via fields in tests/tool/test_research.py.",
    "research.analyzer:VulnerabilityFinding": "Dataclass asserted via fields in tests/lab/test_owasp_coverage.py.",
    "research.threat_model:AttackVector": "Dataclass asserted via fields in tests/tool/test_research.py.",
    "research.threat_model:ThreatActor": "Dataclass asserted via fields in tests/tool/test_research.py.",
    "research.threat_model:ThreatModel": "Class exercised through run_threat_modeling/CLI in tests/tool.",
    # --- constructors/builders invoked through the API surface -------------
    "banking.importer:VulnerableStatementImporter": "Exercised via /import/statement in vulnerable mode (tests/lab/test_ssrf.py).",
    "banking.importer:build_importer": "Exercised via /import/statement in tests/lab/test_ssrf.py.",
    "banking.integrity:LegacyIntegrityStamper": "Exercised via /accounts/ledger/export in vulnerable mode (tests/lab/test_integrity.py).",
    "banking.integrity:build_stamper": "Exercised via /accounts/ledger/export in tests/lab/test_integrity.py.",
    "banking.integrity:ledger_csv_for": "Exercised via /accounts/ledger/export in tests/lab/test_integrity.py.",
    "banking.vulnerable:VulnerableAccountService": "Exercised via build_service in vulnerable mode (tests/lab/*).",
    # --- CLI plumbing -------------------------------------------------------
    "cli.main:build_parser": "Exercised via main() in tests/tool/test_cli.py.",
    "pentest.cli:build_parser": "Exercised via main() in tests/tool/test_cli.py.",
    "research.cli:build_parser": "Exercised via main() in tests/tool/test_cli.py.",
    "research.cli:build_threat_parser": "Exercised via threat-model command in tests/tool/test_cli.py.",
    "research.threat_model:render_text": "Exercised via threat-model CLI output in tests/tool/test_cli.py.",
    "research.threat_model:run_threat_modeling": "Exercised via threat-model CLI in tests/tool/test_cli.py.",
    "pentest.checks:run_checks": "Exercised via the pentest CLI in tests/tool/test_cli.py.",
    "webapp.server:serve_app": "Invoked by cli serve; bind-refusal proven in tests/tool/test_cli.py.",
    # --- per-probe functions exercised through the CHECKS table -------------
    "pentest.checks:Check": "Container for CHECKS; asserted via the table in tests/tool/test_pentest.py.",
    "pentest.checks:check_default_credentials": "Exercised via CHECKS (PT-04) in tests/tool/test_pentest.py.",
    "pentest.checks:check_error_handling": "Exercised via CHECKS (PT-08) in tests/tool/test_pentest.py.",
    "pentest.checks:check_idor": "Exercised via CHECKS (PT-03) in tests/tool/test_pentest.py.",
    "pentest.checks:check_integrity_stamp": "Exercised via CHECKS (PT-10) in tests/tool/test_pentest.py.",
    "pentest.checks:check_login_sqli": "Exercised via CHECKS (PT-01) in tests/tool/test_pentest.py.",
    "pentest.checks:check_outdated_components": "Exercised via CHECKS (PT-09) in tests/tool/test_pentest.py.",
    "pentest.checks:check_reflected_xss": "Exercised via CHECKS (PT-05) in tests/tool/test_pentest.py.",
    "pentest.checks:check_search_sqli": "Exercised via CHECKS (PT-02) in tests/tool/test_pentest.py.",
    "pentest.checks:check_security_headers": "Exercised via CHECKS (PT-06) in tests/tool/test_pentest.py.",
    "pentest.checks:check_session_cookie": "Exercised via CHECKS (PT-07) in tests/tool/test_pentest.py.",
    "pentest.checks:check_ssrf": "Exercised via CHECKS (PT-11) in tests/tool/test_pentest.py.",
    # --- Flask request-lifecycle and security middleware ---------------------
    "storage.database:close_db": "Request teardown; exercised via every HTTP test in tests/lab/.",
    "storage.database:get_db": "Request-scoped connection; exercised via every HTTP test in tests/lab/.",
    "webapp.routes:login_form": "HTTP behaviour tested in tests/lab/test_authentication.py.",
    "webapp.routes:transactions": "HTTP behaviour tested in tests/lab/test_access_control.py.",
    "webapp.security:add_security_headers": "After-request hook; header behaviour tested in tests/lab/test_xss_and_headers.py.",
    "webapp.security:csrf_field": "Template global; CSRF enforcement tested in tests/lab/test_authentication.py.",
    "webapp.security:current_user": "Session helper; exercised via authenticated routes in tests/lab/.",
    "webapp.security:enforce_csrf": "Before-request hook; CSRF behaviour tested in tests/lab/test_authentication.py.",
    "webapp.security:get_csrf_token": "Session helper; exercised via conftest.csrf_token in tests/lab/.",
    "webapp.security:login_required": "Route guard; denial behaviour tested in tests/lab/test_access_control.py.",
    "banking.base:list_accounts_for": "Shared helper exercised through dashboard/transfer behaviour tests.",
    "banking.base:to_transactions": "Row-mapping helper exercised through transaction-list tests.",
    "core.exceptions:AccountLockedError": "Lockout behaviour tested end-to-end in tests/lab/test_authentication.py.",
    "core.exceptions:BankError": "Base class of the concrete exceptions above.",
    "core.exceptions:NotFoundError": "404 behaviour tested end-to-end in tests/lab/test_access_control.py.",
    "core.models:format_cents": "Jinja money filter; rendering tested via dashboard in tests/lab/.",
    "pentest.report:render_json": "Exercised via the pentest CLI --format json in tests/tool/test_cli.py.",
    # --- webapp route handlers: exercised over HTTP, never imported ---------
    "webapp.routes:about": "HTTP behaviour tested in tests/lab/test_component_exposure.py.",
    "webapp.routes:dashboard": "HTTP behaviour tested in tests/lab/test_access_control.py.",
    "webapp.routes:import_statement": "HTTP behaviour tested in tests/lab/test_ssrf.py.",
    "webapp.routes:ledger_export": "HTTP behaviour tested in tests/lab/test_integrity.py.",
    "webapp.routes:logout": "HTTP behaviour tested in tests/lab/test_authentication.py.",
    "webapp.routes:transfer": "HTTP behaviour tested in tests/lab/test_business_logic.py.",
}

# Package names that must contain the contract-checked modules.
_PACKAGES = ("core", "storage", "banking", "webapp", "research", "pentest", "cli")


def _src_modules() -> list[str]:
    """Importable dotted names of every non-``__init__``/``__main__`` module."""
    modules: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC.parent)
        parts = rel.with_suffix("").parts
        if parts[-1] in {"__init__", "__main__"}:
            continue
        modules.append(".".join(("securebank_lab", *parts[1:])))
    return modules


def _public_callables(module_name: str) -> set[str]:
    """Public top-level functions and classes defined in ``module_name``."""
    module = importlib.import_module(module_name)
    names: set[str] = set()
    for attr, value in vars(module).items():
        if attr.startswith("_"):
            continue
        if (
            inspect.isfunction(value) or inspect.isclass(value)
        ) and value.__module__ == module_name:
            names.add(attr)
    return names


def _referenced_names() -> set[str]:
    """Every name and attribute used in test files and shared fixtures."""
    names: set[str] = set()
    paths = [*_TESTS.rglob("test_*.py"), *_TESTS.rglob("conftest.py")]
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, (ast.ImportFrom, ast.Import)):
                for alias in node.names:
                    names.add(alias.asname or alias.name.split(".")[0])
    return names


def test_suite_has_no_empty_packages() -> None:
    for package in ("lab", "tool"):
        files = list((_TESTS / package).glob("test_*.py"))
        assert files, f"tests/{package} must not be empty"


def test_every_public_source_callable_is_tested_or_excluded() -> None:
    referenced = _referenced_names()
    missing: list[str] = []
    for module_name in _src_modules():
        package = module_name.split(".")[1]
        assert package in _PACKAGES, module_name
        for name in _public_callables(module_name):
            key = f"{module_name.split('.', 1)[1]}:{name}"
            if name not in referenced and key not in _EXCLUDED:
                missing.append(key)
    assert not missing, (
        "Public source callables never referenced by any test (add tests or "
        f"document the exclusion in _EXCLUDED): {sorted(missing)}"
    )


def test_bank_never_imports_tool_packages() -> None:
    """The README claims dependency-direction is enforced; this proves it."""
    tool_packages = {"pentest", "research", "cli"}
    for module_name in _src_modules():
        package = module_name.split(".")[1]
        if package in tool_packages:
            continue  # the tool side may import anything
        module = importlib.import_module(module_name)
        assert module.__file__ is not None  # narrows type for mypy
        source = Path(module.__file__).read_text(encoding="utf-8")
        tool_imports: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                parts = node.module.split(".")
                if (
                    parts[0] == "securebank_lab"
                    and parts[1:2]
                    and parts[1] in tool_packages
                ):
                    tool_imports.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    if (
                        parts[0] == "securebank_lab"
                        and parts[1:2]
                        and parts[1] in tool_packages
                    ):
                        tool_imports.add(alias.name)
        assert not tool_imports, (
            f"Bank component module {module_name} imports tool packages "
            f"{sorted(tool_imports)} — this breaks the two-component split."
        )


def test_exclusions_point_at_real_source_functions() -> None:
    """An exclusion may never outlive the function it excuses."""
    live: dict[str, set[str]] = {}
    for module_name in _src_modules():
        short = module_name.split(".", 1)[1]
        live[short] = _public_callables(module_name)
    for key in _EXCLUDED:
        module, name = key.split(":", 1)
        assert name in live.get(module, set()), (
            f"Stale exclusion {key!r}: the function no longer exists in src/."
        )
        assert name not in _referenced_names(), (
            f"Exclusion {key!r} is obsolete: {name} is now referenced by tests."
        )
