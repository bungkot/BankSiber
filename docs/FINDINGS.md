# Findings Catalogue

Canonical list of documented weaknesses and their controls. Each row is
verified in both directions by the test suite; regenerate the machine-readable
version with `securebank-research --mode <mode> --output reports/posture.json`.

| ID | Title | Category | Severity | Vulnerable component | Control (secure component) | Proof |
|---|---|---|---|---|---|---|
| A01-001 | IDOR — transaction access | Broken Access Control | High | `banking/vulnerable.py:get_transactions` | owner check + uniform 404 (`banking/secure.py`) | `tests/test_access_control.py` |
| A02-001 | Plaintext password storage | Cryptographic Failures | Critical | `banking/vulnerable.py:authenticate` | scrypt hash + constant-time check (`banking/secure.py`) | `tests/test_authentication.py` |
| A03-001 | SQL injection (login + search) | Injection | Critical | f-string SQL (`banking/vulnerable.py`) | bound parameters + LIKE escaping (`banking/secure.py`) | `tests/test_injection.py`, probe PT-01/PT-02 |
| A04-001 | Negative/unlimited transfers | Insecure Design | High | `banking/vulnerable.py:transfer` | `parse_amount_cents`, cap, atomic SQL with balance guard | `tests/test_business_logic.py` |
| A05-001 | Weak session secret | Security Misconfiguration | High | `webapp/app.py:_WEAK_SECRET` | `secrets.token_hex(32)` | `tests/test_xss_and_headers.py` |
| A06-001 | Missing security headers | Security Misconfiguration | Medium | no CSP/XFO/nosniff | `webapp/security.py:SECURITY_HEADERS` | probe PT-06 |
| A07-001 | Default credentials, no lockout | Authentication Failures | High | `DEMO_CREDENTIALS` + no counter | hashing, lockout (5→15 min), audit log | `tests/test_authentication.py`, probe PT-04 |
| A08-001 | Reflected XSS | Injection | Medium | `webapp/templates/search.html` (`\|safe`) | autoescaping + strict CSP | `tests/test_xss_and_headers.py`, probe PT-05 |
| A09-001 | Weak session cookie flags | Security Misconfiguration | Low | no HttpOnly/SameSite | `SESSION_COOKIE_*` set in `webapp/app.py` | probe PT-07 |
| A10-001 | Verbose error disclosure | Mishandling of Exceptional Conditions | Medium | `handle_unexpected` returns traceback | generic page + error id; details logged | `tests/test_xss_and_headers.py`, probe PT-08 |

## Status semantics

* **confirmed** — positive evidence of exploitability in the analysed mode.
* **mitigated** — the corresponding control is implemented and proven.
* **inconclusive** (assessment tool only) — no positive evidence; the probe
  could not establish safety (e.g. login failed for probe reasons).

## Remediation mapping

Every fix follows the same pattern: validate at the boundary, authorise at
the object level, fail closed, and add a test that pins the control. When
porting fixes to real code, re-derive severity from the actual system context.
