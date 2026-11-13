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
     (`webapp/server.py:serve_app` → exit code 2).
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
                 → posture per domain + OWASP-mapped findings

attack           securebank-pentest http://127.0.0.1:<port>
                 → evidence-based probe results (vulnerable/not/inconclusive)

verify controls  pytest --cov=securebank_lab
                 → both directions proven per flaw

model risk       securebank-threat-model --mode <mode>
                 → actors, vectors, per-category risk scores, residual risk
```

## Severity and risk scoring

* Severity follows the classical scale (Critical/High/Medium/Low) mapped to
  base scores 9/7/5/3.
* Per-category risk = mean of vector scores, where confirmed findings weigh
  1.0 and mitigated controls 0.3; secondary vectors weigh 0.5×. Scores are
  relative to *this lab*, not a substitute for CVSS in a real engagement.

## Limitations

* The secure build is a *reference* hardening, not a production system: no
  TLS termination, no MFA, no rate limiting beyond lockout, no log
  aggregation.
* A09 (logging/monitoring) is verified **white-box**: black-box probes
  cannot see the server's logs, so the difference is pinned by
  `tests/test_logging.py` and reported by the research analyzer instead of
  the pentest tool (it appears in the report's "not covered" section).
* The threat model is qualitative; numbers support reasoning, they do not
  replace judgement.
* OWASP category names/numbers change between editions — verify against
  <https://owasp.org/Top10/> before citing.
