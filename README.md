# SecureBank Lab — Cybersecurity Research Environment

**Personal research project.** A small online bank implemented **twice** in one
codebase: a deliberately vulnerable build and its hardened counterpart — plus
the research tooling to analyse, attack and verify both.

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
├── core/        configuration, domain models, exceptions, helpers (no I/O deps)
├── storage/     SQLite schema, seed data, connection lifecycle
├── banking/     business logic: AccountService protocol
│                  ├── vulnerable.py  (documented flaws)
│                  └── secure.py      (hardened counterpart)
├── webapp/      Flask factory, thin routes, CSRF/headers/auth guard, server
├── research/    headless analysis: posture analyzer + threat model
├── pentest/     loopback-only non-destructive assessment tool
└── cli/         unified dispatcher: serve | pentest | research | threat-model
```

Key design rules: money is integer cents (never float), no global mutable
state, fail-secure error handling, PEP 484 strict typing.

## Quick start

```bash
python -m venv .venv && .venv\Scripts\activate        # POSIX: source .venv/bin/activate
pip install -e ".[dev]"

# terminal 1: run the bank under study
python -m securebank_lab serve --mode vulnerable --port 5000
python -m securebank_lab serve --mode secure --port 5001

# terminal 2: attack it
python -m securebank_lab pentest http://127.0.0.1:5000
python -m securebank_lab pentest http://127.0.0.1:5001 --fail-on-vulnerable  # CI gate
```

Expected result: **8 confirmed findings** against vulnerable mode, **0**
against secure mode. The same command therefore verifies your own fixes.

Demo accounts (also in `src/securebank_lab/storage/database.py`):

| User     | Vulnerable mode | Secure mode          |
|----------|-----------------|----------------------|
| `jsmith` | `demo1234`      | `Cx7!mango-orbit`    |
| `admin`  | `admin`         | `Qz4#delta-ridge-91` |
| `sgreen` | `password1`     | `Lm9$plum-harbor`    |

## Research tooling (no server required)

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

## Findings to code map

| Finding | Category | Vulnerable code | Fix |
|---|---|---|---|
| 3.1 SQL injection | Injection | `banking/vulnerable.py:authenticate, .search_transactions` | Bound parameters in `banking/secure.py` |
| 3.2 IDOR | Broken Access Control | `.get_transactions` (no owner check) | Ownership check, uniform 404 |
| 3.3 Default creds / no lockout | Authentication Failures | `authenticate`, `DEMO_CREDENTIALS` | Hashed passwords, lockout, audit log |
| 3.4 XSS | Injection | `templates/search.html` (`\|safe`) | Autoescaping, CSP |
| 3.5 Misconfiguration | Security Misconfiguration | weak `SECRET_KEY`, no headers, banner | `webapp/security.py:SECURITY_HEADERS`, random key, cookie flags |
| 3.7 Insecure design | Insecure Design | `.transfer` (negative amounts, no limits) | `parse_amount_cents`, limits, atomic SQL |
| 3.8 Exceptions | Mishandling of Exceptional Conditions | `handle_unexpected` leaks traceback | Generic page + error id, details in log |
| (plaintext storage) | Cryptographic Failures | plaintext `users.password` | scrypt hashes |

Verify category numbering against <https://owasp.org/Top10/> before quoting —
OWASP renames and reorders categories between editions.

## The assessment tool (`securebank-pentest`)

Eight non-destructive probes (login/search SQL injection, IDOR, default
credentials, reflected XSS, security headers, cookie flags, verbose errors).
Built-in guard rails, all covered by tests:

* The HTTP client only accepts `http(s)` URLs whose host is loopback
  (`127.0.0.1`, `::1`, `localhost`); the check lives in the client
  constructor, so no probe can reach another machine.
* The target must identify itself as SecureBank Lab.
* Probes never change data, never brute force, and prove injection with a
  harmless computed marker instead of reading real records.
* Exit codes: `2` = target refused, `1` = flaw found (with `--fail-on-vulnerable`).

Not probed (state-changing): negative transfers and account lockout — proven
in `tests/test_business_logic.py` and `tests/test_authentication.py`.

## Quality gates

```bash
pytest --cov=securebank_lab   # every flaw proven, then proven fixed
ruff format --check . && ruff check .
mypy                          # strict mode
```

## Documentation

* `docs/LAB_GUIDE.md` — hands-on exercises and notes.
* `docs/METHODOLOGY.md` — research methodology and safety design.
* `docs/THREAT_MODEL.md` — documented threat model of the lab itself.
* `docs/FINDINGS.md` — full findings catalogue and remediation mapping.

## License

MIT — see `LICENSE`.
