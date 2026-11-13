# SecureBank Lab â€” Cybersecurity Research Environment

**Personal research project.** A small online bank implemented **twice** in one
codebase: a deliberately vulnerable build and its hardened counterpart â€” plus
the research tooling to analyse, attack and verify both.

The project is **two components**, and everything in this repository belongs
to exactly one of them:

```
        COMPONENT 1 â€” THE BANK (target)          COMPONENT 2 â€” THE TOOL (assessor)
   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”        â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
   â”‚  src/securebank_lab/           â”‚        â”‚  src/securebank_lab/               â”‚
   â”‚    webapp/    Flask bank       â”‚  HTTP   â”‚    pentest/    11 black-box probes â”‚
   â”‚    banking/   vuln + secure    â”‚â—„â”€â”€â”€â”€â”€â”€â”€â”‚    research/   analyzer + threat   â”‚
   â”‚    storage/   SQLite           â”‚        â”‚    cli/        serve | pentest | â€¦ â”‚
   â”‚    core/      shared config    â”‚        â”‚  tests/tool/   tests OF the tool   â”‚
   â”‚  tests/lab/   tests OF the bankâ”‚        â”‚                                    â”‚
   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

* **`vulnerable` mode** â€” modelled on the OWASP Top 10 findings of classic
  pentest case studies (SQL injection, IDOR, default credentials, XSS, weak
  configuration, insecure design, verbose errors).
* **`secure` mode** â€” every documented flaw is fixed and provable.

The workflow is the research loop: **enumerate â†’ attack â†’ verify â†’ model risk**.

> **Safety & ethics.** Vulnerable mode *refuses* to bind to anything except a
> loopback address and the debugger is always off. The assessment tool only
> accepts loopback targets that identify themselves as this lab. Never deploy
> the vulnerable build; never reuse the public demo passwords anywhere real.
> Only test systems you own or have written permission to test.

## Architecture

Layered, dependency-direction enforced (`webapp -> banking -> storage -> core`):

```
src/securebank_lab/
â”œâ”€â”€ COMPONENT 1 â€” THE BANK (what gets attacked)
â”‚   â”œâ”€â”€ core/        configuration, domain models, exceptions, helpers (shared)
â”‚   â”œâ”€â”€ storage/     SQLite schema, seed data, connection lifecycle
â”‚   â”œâ”€â”€ banking/     business logic: AccountService protocol
â”‚   â”‚                 â”œâ”€â”€ vulnerable.py  (documented flaws)
â”‚   â”‚                 â”œâ”€â”€ secure.py      (hardened counterpart)
â”‚   â”‚                 â”œâ”€â”€ integrity.py   (A08: MD5 vs keyed HMAC export stamps)
â”‚   â”‚                 â””â”€â”€ importer.py    (A10: unrestricted vs allowlisted fetch)
â”‚   â””â”€â”€ webapp/      Flask factory, thin routes, CSRF/headers/auth guard, server
â”‚
â””â”€â”€ COMPONENT 2 â€” THE TOOL (what does the attacking/analysing)
    â”œâ”€â”€ pentest/     loopback-only non-destructive assessment tool
    â”œâ”€â”€ research/    headless analysis: posture analyzer + threat model
    â””â”€â”€ cli/         unified dispatcher: serve | pentest | research | threat-model
```

The split matters: the bank never imports from `pentest/`, `research/` or
`cli/`, and the tool never mutates lab data â€” it only reads the bank over
HTTP. `core/` is the shared foundation both components build on.

Key design rules: money is integer cents (never float), no global mutable
state, fail-secure error handling, PEP 484 strict typing.

## Quick start

```bash
python -m venv .venv && .venv\Scripts\activate        # POSIX: source .venv/bin/activate
pip install -e ".[dev]"

# terminal 1 â€” component 1: run the bank under study
python -m securebank_lab serve --mode vulnerable --port 5000
python -m securebank_lab serve --mode secure --port 5001

# terminal 2 â€” component 2: attack it
python -m securebank_lab pentest http://127.0.0.1:5000
python -m securebank_lab pentest http://127.0.0.1:5001 --fail-on-vulnerable  # CI gate
```

Expected result: **11 confirmed findings** against vulnerable mode, **0**
against secure mode. The same command therefore verifies your own fixes.

## Component 1 â€” the bank under study

The target is a complete two-mode bank. Every flaw has a documented fix and
a test that proves both directions. Demo accounts (also in
`src/securebank_lab/storage/database.py`):

| User     | Vulnerable mode | Secure mode          |
|----------|-----------------|----------------------|
| `jsmith` | `demo1234`      | `Cx7!mango-orbit`    |
| `admin`  | `admin`         | `Qz4#delta-ridge-91` |
| `sgreen` | `password1`     | `Lm9$plum-harbor`    |

### How the bank is tested (`tests/lab/`)

Every lab test module targets real functions in `src/` â€” enforced by
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
| `tests/lab/test_owasp_coverage.py` | `research/analyzer.py` â€” meta-test: 10/10 categories confirmed â†’ mitigated |

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

All **ten** OWASP Top 10 (2021) categories are covered â€” verified by
`tests/lab/test_owasp_coverage.py`. Verify numbering against
<https://owasp.org/Top10/> before quoting â€” OWASP renames and reorders
categories between editions.

## Component 2 â€” the assessor tool

The tool side attacks and analyses the bank, and is itself a tested product:

* **`securebank-pentest`** â€” eleven non-destructive probes (login/search SQL
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

* **Posture analysis** â€” authentication, authorisation, cryptography, session
  management and security-header state per mode, plus a structured findings
  list mapped to OWASP Top 10 categories.
* **Threat model** â€” threat-actor profiles derived from confirmed findings,
  primary/secondary attack vectors, per-category risk scores (0.0â€“1.0) and
  residual-risk notes.

See `docs/METHODOLOGY.md` and `docs/THREAT_MODEL.md` for the reasoning.

## Quality gates

```bash
pytest --cov=securebank_lab   # every flaw proven, then proven fixed
ruff format --check . && ruff check .
mypy                          # strict mode
```

## Documentation

* `docs/LAB_GUIDE.md` â€” hands-on exercises and notes.
* `docs/METHODOLOGY.md` â€” research methodology and safety design.
* `docs/THREAT_MODEL.md` â€” documented threat model of the lab itself.
* `docs/FINDINGS.md` â€” full findings catalogue and remediation mapping.

## License

MIT â€” see `LICENSE`.
# Findings Catalogue

Canonical list of documented weaknesses and their controls, mapped to the
**OWASP Top 10 (2021)** â€” all ten categories are covered (verified by
`tests/lab/test_owasp_coverage.py`). Regenerate the machine-readable version with
`securebank-research --mode <mode> --output reports/posture.json`.

| ID | Title | Category | Severity | Vulnerable component | Control (secure component) | Proof |
|---|---|---|---|---|---|---|
| A01-001 | IDOR â€” transaction access | Broken Access Control | High | `banking/vulnerable.py:get_transactions` | owner check + uniform 404 (`banking/secure.py`) | `tests/lab/test_access_control.py` |
| A02-001 | Plaintext password storage | Cryptographic Failures | Critical | `banking/vulnerable.py:authenticate` | scrypt hash + constant-time check (`banking/secure.py`) | `tests/lab/test_authentication.py` |
| A03-001 | SQL injection (login + search) | Injection | Critical | f-string SQL (`banking/vulnerable.py`) | bound parameters + LIKE escaping (`banking/secure.py`) | `tests/lab/test_injection.py`, probe PT-01/PT-02 |
| A04-001 | Negative/unlimited transfers | Insecure Design | High | `banking/vulnerable.py:transfer` | `parse_amount_cents`, cap, atomic SQL with balance guard | `tests/lab/test_business_logic.py` |
| A05-001 | Weak session secret | Security Misconfiguration | High | `webapp/app.py:_WEAK_SECRET` | `secrets.token_hex(32)` | `tests/lab/test_xss_and_headers.py` |
| A05-002 | Verbose error disclosure | Security Misconfiguration | Medium | `handle_unexpected` returns traceback | generic page + error id; details logged | `tests/lab/test_xss_and_headers.py`, probe PT-08 |
| A05-003 | Missing security headers / cookie flags | Security Misconfiguration | Lowâ€“Medium | no CSP/XFO/nosniff; no cookie flags | `webapp/security.py:SECURITY_HEADERS`; `SESSION_COOKIE_*` | probes PT-06/PT-07 |
| A06-001 | Component version disclosure + outdated dependency | Vulnerable & Outdated Components | Medium | `webapp/routes.py:about`; MD5 primitive (`banking/integrity.py`) | minimal `/about`, SBOM stance, `HmacIntegrityStamper` | `tests/lab/test_component_exposure.py`, probe PT-09 |
| A07-001 | Default credentials, no lockout | Authentication Failures | High | `DEMO_CREDENTIALS` + no counter | hashing, lockout (5â†’15 min), audit log | `tests/lab/test_authentication.py`, probe PT-04 |
| A08-001 | Forgeable ledger export stamp | Software & Data Integrity Failures | High | unkeyed MD5 (`banking/integrity.py:LegacyIntegrityStamper`) | keyed HMAC-SHA256 (`HmacIntegrityStamper`) | `tests/lab/test_integrity.py`, probe PT-10 |
| A09-001 | No security event logging or monitoring | Security Logging & Monitoring Failures | High | security events emitted nowhere | structured `securebank.audit` events (auth, denials, rejects) | `tests/lab/test_logging.py` (white-box) |
| A10-001 | SSRF via statement import | Server-Side Request Forgery | High | `banking/importer.py:VulnerableStatementImporter` (any scheme/host) | https + host allowlist, fails closed (`SecureStatementImporter`) | `tests/lab/test_ssrf.py`, probe PT-11 |
| A03-002 | Reflected XSS | Injection | Medium | `webapp/templates/search.html` (`\|safe`) | autoescaping + strict CSP | `tests/lab/test_xss_and_headers.py`, probe PT-05 |

## Status semantics

* **confirmed** â€” positive evidence of exploitability in the analysed mode.
* **mitigated** â€” the corresponding control is implemented and proven.
* **inconclusive** (assessment tool only) â€” no positive evidence; the probe
  could not establish safety (e.g. login failed for probe reasons).

## Remediation mapping

Every fix follows the same pattern: validate at the boundary, authorise at
the object level, fail closed, and add a test that pins the control. When
porting fixes to real code, re-derive severity from the actual system context.
# Lab Guide

Hands-on exercises for the SecureBank Lab. Work through them in order; each
exercise follows the same loop:

1. **Attack** the vulnerable build and capture evidence.
2. **Verify** the finding with the assessment tool or a test.
3. **Study** the secure counterpart.
4. **Re-verify**: the same probe must now report `not_vulnerable`.

Start the target (one terminal per mode):

```bash
python -m securebank_lab serve --mode vulnerable --port 5000
python -m securebank_lab serve --mode secure --port 5001
```

## Exercise 1 â€” SQL injection (login)

```
username: admin'--      password: anything
```

Observed: authentication bypass (HTTP 302). Now try `x' ORDER BY 99--` and
note the raw database error â€” proof that input becomes SQL.

* Vulnerable code: `banking/vulnerable.py:authenticate`.
* Fix to study: `banking/secure.py:authenticate` (bound parameters).
* Probe: `securebank-pentest` check PT-01.

## Exercise 2 â€” SQL injection (search, UNION-based)

Log in as `jsmith` and search for:

```
zzz' UNION SELECT 1, 1, 'PTMARK42', 0--
```

The marker appears inside the result table: you executed your own SELECT.

* Vulnerable code: `banking/vulnerable.py:search_transactions`.
* Fix to study: bound parameters + LIKE-escaping + length limit.

## Exercise 3 â€” IDOR

As `jsmith`, open `/accounts/1002/transactions` (owned by `sgreen`).

* Vulnerable build: HTTP 200 with another customer's ledger.
* Secure build: uniform 404 â€” no enumeration possible.
* Study `banking/secure.py:get_transactions`.

## Exercise 4 â€” Default credentials

Log in as `admin`/`admin` against vulnerable mode. Then study the secure
mode: hashed passwords, progressive lockout (5 attempts â†’ 15 minutes) and the
audit log lines emitted by `securebank.audit`.

## Exercise 5 â€” Reflected XSS

Search for `<i id=ptprobe>` and view source: the markup is reflected raw.
Secure mode HTML-encodes on output *and* sends a strict CSP.

## Exercise 6 â€” Security misconfiguration

Compare response headers of both modes (`curl -i`). Vulnerable mode sends no
`Content-Security-Policy`, no `X-Frame-Options`, and a `Server` banner that
leaks framework/version. Secure mode fixes all three. Also note the weak
session secret in `webapp/app.py` (`_WEAK_SECRET`).

## Exercise 7 â€” Insecure design (transfers)

Transfer `-1000` between your own accounts: the negative amount *reverses*
the direction of the flow. Try a decimal amount with three decimals, or an
amount above the limit. Study `parse_amount_cents` and the atomic
`UPDATE ... WHERE balance_cents >= ?` in `banking/secure.py`.

## Exercise 8 â€” Verbose errors

POST a non-numeric amount in vulnerable mode: the response body contains the
full Python traceback. Secure mode returns a generic 500 page with an error
id; details are logged server-side only.

## Exercise 9 â€” Automate it

```bash
securebank-pentest http://127.0.0.1:5000                 # Markdown report
securebank-pentest http://127.0.0.1:5000 --format json --output report.json
securebank-pentest http://127.0.0.1:5001 --fail-on-vulnerable
```

## Exercise 10 â€” Model the risk

```bash
securebank-research --mode vulnerable
securebank-threat-model --mode vulnerable
```

Compare risk scores between modes. For every confirmed finding, write down:
the affected component, the minimal fix, and how the *test suite* proves the
fix. That mapping is the deliverable of this lab â€” see `docs/FINDINGS.md`.

## Exercise 11 â€” Outdated components (A06)

Visit `/about` without logging in: vulnerable mode hands over exact Flask and
Werkzeug versions plus a pinned past-EOL dependency â€” a free shopping list
for matching public exploits. Secure mode answers without any component
detail. Note how the `Server` banner alone (seen in Exercise 6) already
leaks an exact version.

## Exercise 12 â€” Data integrity failure (A08)

Log in and open `/accounts/ledger/export`. Vulnerable mode stamps the CSV
with **unkeyed MD5**: edit the downloaded file (change an amount), recompute
`md5(file)` with any tool, and the stamp matches â€” tampering is undetectable.
Secure mode uses keyed **HMAC-SHA256**: the probe (PT-10) proves it cannot
forge the stamp without the server secret.

## Exercise 13 â€” No logging, no monitoring (A09)

Run the attacks from Exercises 1â€“5 again while watching the server console.
Vulnerable mode records *nothing*: failed logins, IDOR access and rejected
requests all leave no trace â€” an attacker can be as noisy as they like.
Secure mode writes structured `securebank.audit` events (`login_failed`,
`access_denied`, `import_rejected`); `tests/lab/test_logging.py` pins this
white-box difference.

## Exercise 14 â€” SSRF (A10)

Log in as `jsmith` and use the Import page (`/import/statement`). Feed the
vulnerable build:

```
file:///C:/Windows/win.ini          (Windows)
file:///etc/hostname                (POSIX)
http://127.0.0.1:5000/login         (its own internal page)
```

The server fetches and displays it â€” that is server-side request forgery,
including arbitrary local file read. Secure mode enforces https + a
destination-host allowlist and rejects everything else (probe PT-11 proves
it with the lab's own login page as the fetch target).
# Research Methodology

## Goal

A controlled, local-only environment to study the full vulnerability
lifecycle: introduction, discovery, exploitation, remediation and risk
modelling. The lab implements the same banking domain twice so that every
security control can be evaluated *against its exact absence*.

## Design principles

1. **Dual implementation, one contract.** Both modes satisfy the same
   `AccountService` protocol (`banking/base.py`). Differences in security
   posture are therefore attributable to implementation choices, not to
   differing functionality.
2. **Local-only by construction.**
   * The vulnerable server refuses non-loopback bind addresses
     (`webapp/server.py:serve_app` â†’ exit code 2).
   * The assessment client refuses non-loopback targets in its constructor
     (`pentest/client.py:LabClient.__init__`).
   * The client additionally requires the target to identify itself as
     SecureBank Lab, protecting other local services.
3. **Non-destructive assessment.** Proves never mutate data, never brute
   force, and prove injection with a computed marker (`PTMARK42`) instead of
   extracting real records. State-changing weaknesses are covered by
   unit/integration tests rather than live probes.
4. **Fail-secure defaults.** Secure mode: generic errors with correlation
   ids, strict CSP, `HttpOnly`/`SameSite` cookies, CSRF enforcement,
   uniform 404s (no enumeration), integer-cents money arithmetic.
5. **Everything is provable.** Every finding is backed by at least one test
   (attack proven) *and* one test in secure mode (control proven).

## Analysis workflow

```
enumerate        securebank-research --mode <mode>
                 â†’ posture per domain + OWASP-mapped findings

attack           securebank-pentest http://127.0.0.1:<port>
                 â†’ evidence-based probe results (vulnerable/not/inconclusive)

verify controls  pytest --cov=securebank_lab
                 â†’ both directions proven per flaw

model risk       securebank-threat-model --mode <mode>
                 â†’ actors, vectors, per-category risk scores, residual risk
```

## Severity and risk scoring

* Severity follows the classical scale (Critical/High/Medium/Low) mapped to
  base scores 9/7/5/3.
* Per-category risk = mean of vector scores, where confirmed findings weigh
  1.0 and mitigated controls 0.3; secondary vectors weigh 0.5Ã—. Scores are
  relative to *this lab*, not a substitute for CVSS in a real engagement.

## Limitations

* The secure build is a *reference* hardening, not a production system: no
  TLS termination, no MFA, no rate limiting beyond lockout, no log
  aggregation.
* A09 (logging/monitoring) is verified **white-box**: black-box probes
  cannot see the server's logs, so the difference is pinned by
  `tests/lab/test_logging.py` and reported by the research analyzer instead of
  the pentest tool (it appears in the report's "not covered" section).
* The threat model is qualitative; numbers support reasoning, they do not
  replace judgement.
* OWASP category names/numbers change between editions â€” verify against
  <https://owasp.org/Top10/> before citing.
# Threat Model â€” SecureBank Lab

Reference model produced with `securebank-threat-model`; regenerate anytime:

```bash
securebank-threat-model --mode vulnerable
securebank-threat-model --mode secure
```

## Scope and assets

| Asset | Sensitive? | Note |
|---|---|---|
| `users.password` (plaintext, vulnerable mode) | Critical | direct credential exposure |
| `transactions.description` | High | contains confidential business entries |
| `accounts.balance_cents` | High | financial integrity |
| Session cookie (signed Flask session) | High | forgeable with weak secret |

## Threat actors (vulnerable mode)

| ID | Actor | Skill | Motivation | Capabilities |
|---|---|---|---|---|
| TA-001 | Data Extractor | competent | data theft | UNION/error-based SQLi |
| TA-002 | Credential Brute-Forcer | script kiddie | unauthorised access | published defaults, no lockout |
| TA-003 | Session Hijacker | competent | unauthorised access | cookie forgery (weak secret), CSRF |
| TA-004 | Privilege Escalator | competent | data theft | IDOR on account ids |
| TA-005 | Reconnaissance Actor | script kiddie | information gathering | stack traces, verbose errors |
| TA-006 | Component Reconnaissance | script kiddie | information gathering | version fingerprinting, EOL dependency lookup |
| TA-007 | Data Meddler | competent | fraud | export tampering, unkeyed MD5 stamp forgery |
| TA-008 | Internal Service Prober | competent | information gathering | SSRF, `file://` abuse, internal scanning |
| â€” | Silent Intruder (implicit) | any | any | benefits from A09: no security events are logged |

## Attack vectors (summary)

| ID | Vector | OWASP | Difficulty | Status (vuln â†’ secure) |
|---|---|---|---|---|
| A03-001 | SQLi via search (UNION) | A03 | low | confirmed â†’ mitigated |
| A01-001 | IDOR on `/accounts/{id}/transactions` | A01 | medium | confirmed â†’ mitigated |
| A02-001 | Plaintext password storage | A02 | medium | confirmed â†’ mitigated |
| A07-001 | Default credentials, no lockout | A07 | low | confirmed â†’ mitigated |
| A05-001 | Weak `SECRET_KEY` | A05 | medium | confirmed â†’ mitigated |
| A04-001 | Negative/unlimited transfers | A04 | medium | confirmed â†’ mitigated |
| A05-002 | Stack-trace disclosure | A05 | medium | confirmed â†’ mitigated |
| A06-001 | Version disclosure + EOL dependency | A06 | low | confirmed â†’ mitigated |
| A08-001 | Forgeable MD5 export stamp | A08 | low | confirmed â†’ mitigated |
| A09-001 | No security logging/monitoring | A09 | low | confirmed â†’ mitigated |
| A10-001 | SSRF via statement import (`file://`, internal http) | A10 | low | confirmed â†’ mitigated |
| PT-05/06/07 | XSS, missing headers, cookie flags | â€” | lowâ€“medium | confirmed â†’ mitigated |

## Risk picture (relative, lab-scoped)

Vulnerable mode: every category above scores at full severity weight;
Injection and Cryptographic Failures dominate (Critical). Secure mode: all
vectors weigh 0.3 and risk concentrates in *residual* concerns only.

## Residual risks (secure mode)

* Demo credentials are public â€” the lab models *awareness*, not secrecy.
* Lockout is per-account and in-memory-of-DB only; distributed credential
  stuffing would need rate limiting at the proxy layer.
* No TLS in the lab: HSTS/`Secure` flags only engage with `cookie_secure=True`.
* Audit logging is a Python logger â€” no integrity protection or alerting
  pipeline (modelled as `log_integrity_protection: none` in the research
  analyzer); a production deployment would ship logs to centralised,
  integrity-protected storage.
* The `statements.lab.internal` allowlist is fictional â€” it demonstrates the
  *control shape* (deny by default), not a real integration.

## Assumptions and trust boundaries

* The researcher is the only user; the browser is untrusted input.
* Trust boundary = HTTP request â†’ Flask â†’ service â†’ SQLite.
* Vulnerable mode must never be reachable off-host (enforced twice:
  server bind check and client target check).
