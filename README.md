# SecureBank Lab — Cybersecurity Research Environment

[![CI](https://github.com/bungkot/BankSiber/actions/workflows/ci.yml/badge.svg)](https://github.com/bungkot/BankSiber/actions/workflows/ci.yml)
[![Release](https://github.com/bungkot/BankSiber/actions/workflows/release.yml/badge.svg)](https://github.com/bungkot/BankSiber/actions/workflows/release.yml)
[![Codecov](https://codecov.io/gh/bungkot/BankSiber/graph/badge.svg)](https://codecov.io/gh/bungkot/BankSiber)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue?logo=python&logoColor=white)
![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230?logo=ruff)
![Types: mypy strict](https://img.shields.io/badge/types-mypy%20strict-2A6DB2)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

**Personal research project.** A small online bank implemented **twice** in one
codebase: a deliberately vulnerable build and its hardened counterpart — plus
the research tooling to analyse, attack and verify both.

The project is **two components**, and everything in this repository belongs
to exactly one of them:

```
        COMPONENT 1 — THE BANK (target)          COMPONENT 2 — THE TOOL (assessor)
   ┌────────────────────────────────┐        ┌────────────────────────────────────┐
   │  src/securebank_lab/           │        │  src/securebank_lab/               │
   │    webapp/    Flask bank       │  HTTP   │    pentest/    11 black-box probes │
   │    banking/   vuln + secure    │◄───────│    research/   analyzer + threat   │
   │    storage/   SQLite           │        │    cli/        serve | pentest | … │
   │    core/      shared config    │        │  tests/tool/   tests OF the tool   │
   │  tests/lab/   tests OF the bank│        │                                    │
   └────────────────────────────────┘        └────────────────────────────────────┘
```

* **`vulnerable` mode** — modelled on the OWASP Top 10 findings of classic
  pentest case studies (SQL injection, IDOR, default credentials, XSS, weak
  configuration, insecure design, verbose errors).
* **`secure` mode** — every documented flaw is fixed and provable.

The workflow is the research loop: **enumerate → attack → verify → model risk**.

> **Safety & ethics.** Vulnerable mode *refuses* to bind to anything except a
> loopback address and the debugger is always off. The assessment tool only
> accepts loopback targets that identify themselves as this lab. Never deploy
> the vulnerable build; never reuse the public demo passwords anywhere real.
> Only test systems you own or have written permission to test.

## Architecture

Layered, dependency-direction enforced (`webapp -> banking -> storage -> core`):

```
src/securebank_lab/
├── COMPONENT 1 — THE BANK (what gets attacked)
│   ├── core/        configuration, domain models, exceptions, helpers (shared)
│   ├── storage/     SQLite schema, seed data, connection lifecycle
│   ├── banking/     business logic: AccountService protocol
│   │                 ├── vulnerable.py  (documented flaws)
│   │                 ├── secure.py      (hardened counterpart)
│   │                 ├── integrity.py   (A08: MD5 vs keyed HMAC export stamps)
│   │                 └── importer.py    (A10: unrestricted vs allowlisted fetch)
│   └── webapp/      Flask factory, thin routes, CSRF/headers/auth guard, server
│
└── COMPONENT 2 — THE TOOL (what does the attacking/analysing)
    ├── pentest/     loopback-only non-destructive assessment tool
    ├── research/    headless analysis: posture analyzer + threat model
    └── cli/         unified dispatcher: serve | pentest | research | threat-model
```

The split matters: the bank never imports from `pentest/`, `research/` or
`cli/`, and the tool never mutates lab data — it only reads the bank over
HTTP. `core/` is the shared foundation both components build on.

Key design rules: money is integer cents (never float), no global mutable
state, fail-secure error handling, PEP 484 strict typing.

## Quick start

```bash
python -m venv .venv && .venv\Scripts\activate        # POSIX: source .venv/bin/activate
pip install -e ".[dev]"

# terminal 1 — component 1: run the bank under study
python -m securebank_lab serve --mode vulnerable --port 5000
python -m securebank_lab serve --mode secure --port 5001

# terminal 2 — component 2: attack it
python -m securebank_lab pentest http://127.0.0.1:5000
python -m securebank_lab pentest http://127.0.0.1:5001 --fail-on-vulnerable  # CI gate
```

Expected result: **11 confirmed findings** against vulnerable mode, **0**
against secure mode. The same command therefore verifies your own fixes.

## Component 1 — the bank under study

The target is a complete two-mode bank. Every flaw has a documented fix and
a test that proves both directions. Demo accounts (also in
`src/securebank_lab/storage/database.py`):

| User     | Vulnerable mode | Secure mode          |
|----------|-----------------|----------------------|
| `jsmith` | `demo1234`      | `Cx7!mango-orbit`    |
| `admin`  | `admin`         | `Qz4#delta-ridge-91` |
| `sgreen` | `password1`     | `Lm9$plum-harbor`    |

### How the bank is tested (`tests/lab/`)

Every lab test module targets real functions in `src/` — enforced by
`tests/lab/test_source_contract.py`, which fails if any public function or class
in `securebank_lab` is never referenced by the suite (or is not explicitly
excluded with a reason).

| Suite | Exercises (src) |
|---|---|
| `tests/lab/test_authentication.py` | `banking/vulnerable.py:authenticate`, `banking/secure.py:authenticate`, lockout, audit log |
| `tests/lab/test_injection.py` | `search_transactions` / login SQL in both implementations |
| `tests/lab/test_access_control.py` | `get_transactions` owner check, 404 uniformity, `login_required` |
| `tests/lab/test_business_logic.py` | `transfer`, `parse_amount_cents`, atomic SQL limits |
| `tests/lab/test_xss_and_headers.py` | `webapp/security.py:SECURITY_HEADERS`, escaping, error handling |
| `tests/lab/test_component_exposure.py` | `webapp/routes.py:about` (A06) |
| `tests/lab/test_integrity.py` | `banking/integrity.py` stampers, `ledger_csv_for` (A08) |
| `tests/lab/test_ssrf.py` | `banking/importer.py` both importers, `/import/statement` (A10) |
| `tests/lab/test_logging.py` | `securebank.audit` events in both modes (A09) |
| `tests/lab/test_owasp_coverage.py` | `research/analyzer.py` — meta-test: 10/10 categories confirmed → mitigated |

### Findings to code map

| Finding | Category | Vulnerable code | Fix |
|---|---|---|---|
| 3.1 SQL injection | Injection (A03) | `banking/vulnerable.py:authenticate, .search_transactions` | Bound parameters in `banking/secure.py` |
| 3.2 IDOR | Broken Access Control (A01) | `.get_transactions` (no owner check) | Ownership check, uniform 404 |
| 3.3 Default creds / no lockout | Authentication Failures (A07) | `authenticate`, `DEMO_CREDENTIALS` | Hashed passwords, lockout, audit log |
| 3.4 XSS | Injection (A03) | `templates/search.html` (`\|safe`) | Autoescaping, CSP |
| 3.5 Misconfiguration | Security Misconfiguration (A05) | weak `SECRET_KEY`, no headers, banner | `webapp/security.py:SECURITY_HEADERS`, random key, cookie flags |
| 3.7 Insecure design | Insecure Design (A04) | `.transfer` (negative amounts, no limits) | `parse_amount_cents`, limits, atomic SQL |
| 3.8 Exceptions | Security Misconfiguration (A05) | `handle_unexpected` leaks traceback | Generic page + error id, details in log |
| (plaintext storage) | Cryptographic Failures (A02) | plaintext `users.password` | scrypt hashes |
| Version disclosure + EOL dependency | Vulnerable & Outdated Components (A06) | `webapp/routes.py:about`, MD5 primitive | Minimal `/about`, inventoried deps, HMAC |
| Unkeyed MD5 export stamp | Software & Data Integrity Failures (A08) | `banking/integrity.py:LegacyIntegrityStamper` | `HmacIntegrityStamper` (keyed HMAC-SHA256) |
| Silent security events | Security Logging & Monitoring Failures (A09) | no audit logging anywhere | structured `securebank.audit` events |
| Statement import fetches any URL | Server-Side Request Forgery (A10) | `banking/importer.py:VulnerableStatementImporter` | https + host allowlist, fails closed |

All **ten** OWASP Top 10 (2021) categories are covered — verified by
`tests/lab/test_owasp_coverage.py`. Verify numbering against
<https://owasp.org/Top10/> before quoting — OWASP renames and reorders
categories between editions.

## Component 2 — the assessor tool

The tool side attacks and analyses the bank, and is itself a tested product:

* **`securebank-pentest`** — eleven non-destructive probes (login/search SQL
  injection, IDOR, default credentials, reflected XSS, security headers,
  cookie flags, verbose errors, component disclosure, forgeable export stamp,
  SSRF). Built-in guard rails, all covered by tests:

* The HTTP client only accepts `http(s)` URLs whose host is loopback
  (`127.0.0.1`, `::1`, `localhost`); the check lives in the client
  constructor, so no probe can reach another machine.
* The target must identify itself as SecureBank Lab.
* Probes never change data, never brute force, and prove injection with a
  harmless computed marker instead of reading real records.
* Exit codes: `2` = target refused, `1` = flaw found (with `--fail-on-vulnerable`).

### How the tool is tested (`tests/tool/`)

| Suite | Exercises (src) |
|---|---|
| `tests/tool/test_pentest.py` | `pentest/checks.py:CHECKS`, `client.py:LabClient`, guard rails, repeatability |
| `tests/tool/test_research.py` | `research/analyzer.py:ResearchAnalyzer`, `threat_model.py:run_threat_modeling` |
| `tests/tool/test_cli.py` | `cli/main.py`, `core/netutil.py:is_loopback`, `webapp/server.py:QuietBannerHandler` |

Not probed (state-changing or server-side-only): negative transfers and
account lockout are proven in `tests/lab/test_business_logic.py` and
`tests/lab/test_authentication.py`; security logging/monitoring (A09) needs
server-side log visibility and is proven in `tests/lab/test_logging.py`.

### Research tooling (no server required)

```bash
securebank-research --mode vulnerable --output reports/posture.json
securebank-research --mode secure
securebank-threat-model --mode vulnerable            # actors, vectors, risk scores
securebank-threat-model --mode secure --output reports/threat-model.json
```

The research package runs headlessly against the seeded databases and produces:

* **Posture analysis** — authentication, authorisation, cryptography, session
  management and security-header state per mode, plus a structured findings
  list mapped to OWASP Top 10 categories.
* **Threat model** — threat-actor profiles derived from confirmed findings,
  primary/secondary attack vectors, per-category risk scores (0.0–1.0) and
  residual-risk notes.

See `docs/METHODOLOGY.md` and `docs/THREAT_MODEL.md` for the reasoning.

## Quality gates

```bash
pytest --cov=securebank_lab   # every flaw proven, then proven fixed
ruff format --check . && ruff check .
mypy                          # strict mode
```

The same gates — plus the full serve → pentest → verify behaviour loop and the
headless research tooling — run in CI on every push and pull request
(`.github/workflows/ci.yml`); version tags are built and released by
`.github/workflows/release.yml`.

## Documentation

* `docs/LAB_GUIDE.md` — hands-on exercises and notes.
* `docs/METHODOLOGY.md` — research methodology and safety design.
* `docs/THREAT_MODEL.md` — documented threat model of the lab itself.
* `docs/FINDINGS.md` — full findings catalogue and remediation mapping.

## Repository

* Clone: `git clone https://github.com/bungkot/BankSiber.git`
* Issues: <https://github.com/bungkot/BankSiber/issues>

## License

MIT — see `LICENSE`.
