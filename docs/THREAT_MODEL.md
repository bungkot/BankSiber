# Threat Model — SecureBank Lab

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

## Attack vectors (summary)

| ID | Vector | OWASP | Difficulty | Status (vuln → secure) |
|---|---|---|---|---|
| A03-001 | SQLi via search (UNION) | A03 | low | confirmed → mitigated |
| A01-001 | IDOR on `/accounts/{id}/transactions` | A01 | medium | confirmed → mitigated |
| A02-001 | Plaintext password storage | A02 | medium | confirmed → mitigated |
| A07-001 | Default credentials, no lockout | A07 | low | confirmed → mitigated |
| A05-001 | Weak `SECRET_KEY` | A05 | medium | confirmed → mitigated |
| A04-001 | Negative/unlimited transfers | A04 | medium | confirmed → mitigated |
| A10-001 | Stack-trace disclosure | A10 | medium | confirmed → mitigated |
| PT-05/06/07 | XSS, missing headers, cookie flags | — | low–medium | confirmed → mitigated |

## Risk picture (relative, lab-scoped)

Vulnerable mode: every category above scores at full severity weight;
Injection and Cryptographic Failures dominate (Critical). Secure mode: all
vectors weigh 0.3 and risk concentrates in *residual* concerns only.

## Residual risks (secure mode)

* Demo credentials are public — the lab models *awareness*, not secrecy.
* Lockout is per-account and in-memory-of-DB only; distributed credential
  stuffing would need rate limiting at the proxy layer.
* No TLS in the lab: HSTS/`Secure` flags only engage with `cookie_secure=True`.
* Audit logging is a Python logger — no integrity protection or alerting.

## Assumptions and trust boundaries

* The researcher is the only user; the browser is untrusted input.
* Trust boundary = HTTP request → Flask → service → SQLite.
* Vulnerable mode must never be reachable off-host (enforced twice:
  server bind check and client target check).
