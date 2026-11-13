"""SecureBank Lab - a local cybersecurity research environment.

The same small online bank is implemented twice:

* ``vulnerable`` mode - deliberately flawed (OWASP Top 10 style findings),
  for attack research and verification.
* ``secure`` mode - the hardened counterpart that fixes every documented
  flaw, for control validation.

Layered architecture::

    core       - configuration, domain models, exceptions, helpers
    storage    - SQLite schema, seed data, connections
    banking    - business logic (vulnerable + secure implementations)
    webapp     - Flask application, routes, HTTP protections
    research   - posture analysis and threat modelling (headless)
    pentest    - loopback-only non-destructive assessment tool
    cli        - unified command line dispatcher

Everything runs locally; vulnerable mode refuses to bind to a non-loopback
address. The demo passwords are public and must never be reused anywhere.
"""

from __future__ import annotations

from securebank_lab.banking import (
    AccountService,
    SecureAccountService,
    VulnerableAccountService,
    build_service,
)
from securebank_lab.core import (
    Account,
    AccountLockedError,
    BankError,
    Mode,
    NotFoundError,
    Settings,
    Transaction,
    User,
    ValidationError,
    __version__,
    format_cents,
    is_loopback,
)
from securebank_lab.research import (
    AttackSurface,
    ResearchAnalyzer,
    ResearchReport,
    VulnerabilityFinding,
    run_research_analysis,
)
from securebank_lab.storage import DEMO_CREDENTIALS, connect, init_db
from securebank_lab.webapp import SECURITY_HEADERS, create_app

__all__ = [
    "DEMO_CREDENTIALS",
    "SECURITY_HEADERS",
    "Account",
    "AccountLockedError",
    "AccountService",
    "AttackSurface",
    "BankError",
    "Mode",
    "NotFoundError",
    "ResearchAnalyzer",
    "ResearchReport",
    "SecureAccountService",
    "Settings",
    "Transaction",
    "User",
    "ValidationError",
    "VulnerabilityFinding",
    "VulnerableAccountService",
    "__version__",
    "build_service",
    "connect",
    "create_app",
    "format_cents",
    "init_db",
    "is_loopback",
    "run_research_analysis",
]
