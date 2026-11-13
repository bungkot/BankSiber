# Findings Catalogue

Canonical list of documented weaknesses and their controls, mapped to the
**OWASP Top 10 (2021)** — all ten categories are covered (verified by
`tests/test_owasp_coverage.py`). Regenerate the machine-readable version with
`securebank-research --mode <mode> --output reports/posture.json`.

| ID | Title | Category | Severity | Vulnerable component | Control (secure component) | Proof |
|---|---|---|---|---|---|---|
| A01-001 | IDOR — transaction access | Broken Access Control | High | `banking/vulnerable.py:get_transactions` | owner check + uniform 404 (`banking/secure.py`) | `tests/test_access_control.py` |
| A02-001 | Plaintext password storage | Cryptographic Failures | Critical | `banking/vulnerable.py:authenticate` | scrypt hash + constant-time check (`banking/secure.py`) | `tests/test_authentication.py` |
| A03-001 | SQL injection (login + search) | Injection | Critical | f-string SQL (`banking/vulnerable.py`) | bound parameters + LIKE escaping (`banking/secure.py`) | `tests/test_injection.py`, probe PT-01/PT-02 |
| A04-001 | Negative/unlimited transfers | Insecure Design | High | `banking/vulnerable.py:transfer` | `parse_amount_cents`, cap, atomic SQL with balance guard | `tests/test_business_logic.py` |
| A05-001 | Weak session secret | Security Misconfiguration | High | `webapp/app.py:_WEAK_SECRET` | `secrets.token_hex(32)` | `tests/test_xss_and_headers.py` |
| A05-002 | Verbose error disclosure | Security Misconfiguration | Medium | `handle_unexpected` returns traceback | generic page + error id; details logged | `tests/test_xss_and_headers.py`, probe PT-08 |
| A05-003 | Missing security headers / cookie flags | Security Misconfiguration | Low–Medium | no CSP/XFO/nosniff; no cookie flags | `webapp/security.py:SECURITY_HEADERS`; `SESSION_COOKIE_*` | probes PT-06/PT-07 |
| A06-001 | Component version disclosure + outdated dependency | Vulnerable & Outdated Components | Medium | `webapp/routes.py:about`; MD5 primitive (`banking/integrity.py`) | minimal `/about`, SBOM stance, `HmacIntegrityStamper` | `tests/test_component_exposure.py`, probe PT-09 |
| A07-001 | Default credentials, no lockout | Authentication Failures | High | `DEMO_CREDENTIALS` + no counter | hashing, lockout (5→15 min), audit log | `tests/test_authentication.py`, probe PT-04 |
| A08-001 | Forgeable ledger export stamp | Software & Data Integrity Failures | High | unkeyed MD5 (`banking/integrity.py:LegacyIntegrityStamper`) | keyed HMAC-SHA256 (`HmacIntegrityStamper`) | `tests/test_integrity.py`, probe PT-10 |
| A09-001 | No security event logging or monitoring | Security Logging & Monitoring Failures | High | security events emitted nowhere | structured `securebank.audit` events (auth, denials, rejects) | `tests/test_logging.py` (white-box) |
| A10-001 | SSRF via statement import | Server-Side Request Forgery | High | `banking/importer.py:VulnerableStatementImporter` (any scheme/host) | https + host allowlist, fails closed (`SecureStatementImporter`) | `tests/test_ssrf.py`, probe PT-11 |
| A03-002 | Reflected XSS | Injection | Medium | `webapp/templates/search.html` (`\|safe`) | autoescaping + strict CSP | `tests/test_xss_and_headers.py`, probe PT-05 |

## Status semantics

* **confirmed** — positive evidence of exploitability in the analysed mode.
* **mitigated** — the corresponding control is implemented and proven.
* **inconclusive** (assessment tool only) — no positive evidence; the probe
  could not establish safety (e.g. login failed for probe reasons).

## Remediation mapping

Every fix follows the same pattern: validate at the boundary, authorise at
the object level, fail closed, and add a test that pins the control. When
porting fixes to real code, re-derive severity from the actual system context.
