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

## Exercise 1 — SQL injection (login)

```
username: admin'--      password: anything
```

Observed: authentication bypass (HTTP 302). Now try `x' ORDER BY 99--` and
note the raw database error — proof that input becomes SQL.

* Vulnerable code: `banking/vulnerable.py:authenticate`.
* Fix to study: `banking/secure.py:authenticate` (bound parameters).
* Probe: `securebank-pentest` check PT-01.

## Exercise 2 — SQL injection (search, UNION-based)

Log in as `jsmith` and search for:

```
zzz' UNION SELECT 1, 1, 'PTMARK42', 0--
```

The marker appears inside the result table: you executed your own SELECT.

* Vulnerable code: `banking/vulnerable.py:search_transactions`.
* Fix to study: bound parameters + LIKE-escaping + length limit.

## Exercise 3 — IDOR

As `jsmith`, open `/accounts/1002/transactions` (owned by `sgreen`).

* Vulnerable build: HTTP 200 with another customer's ledger.
* Secure build: uniform 404 — no enumeration possible.
* Study `banking/secure.py:get_transactions`.

## Exercise 4 — Default credentials

Log in as `admin`/`admin` against vulnerable mode. Then study the secure
mode: hashed passwords, progressive lockout (5 attempts → 15 minutes) and the
audit log lines emitted by `securebank.audit`.

## Exercise 5 — Reflected XSS

Search for `<i id=ptprobe>` and view source: the markup is reflected raw.
Secure mode HTML-encodes on output *and* sends a strict CSP.

## Exercise 6 — Security misconfiguration

Compare response headers of both modes (`curl -i`). Vulnerable mode sends no
`Content-Security-Policy`, no `X-Frame-Options`, and a `Server` banner that
leaks framework/version. Secure mode fixes all three. Also note the weak
session secret in `webapp/app.py` (`_WEAK_SECRET`).

## Exercise 7 — Insecure design (transfers)

Transfer `-1000` between your own accounts: the negative amount *reverses*
the direction of the flow. Try a decimal amount with three decimals, or an
amount above the limit. Study `parse_amount_cents` and the atomic
`UPDATE ... WHERE balance_cents >= ?` in `banking/secure.py`.

## Exercise 8 — Verbose errors

POST a non-numeric amount in vulnerable mode: the response body contains the
full Python traceback. Secure mode returns a generic 500 page with an error
id; details are logged server-side only.

## Exercise 9 — Automate it

```bash
securebank-pentest http://127.0.0.1:5000                 # Markdown report
securebank-pentest http://127.0.0.1:5000 --format json --output report.json
securebank-pentest http://127.0.0.1:5001 --fail-on-vulnerable
```

## Exercise 10 — Model the risk

```bash
securebank-research --mode vulnerable
securebank-threat-model --mode vulnerable
```

Compare risk scores between modes. For every confirmed finding, write down:
the affected component, the minimal fix, and how the *test suite* proves the
fix. That mapping is the deliverable of this lab — see `docs/FINDINGS.md`.

## Exercise 11 — Outdated components (A06)

Visit `/about` without logging in: vulnerable mode hands over exact Flask and
Werkzeug versions plus a pinned past-EOL dependency — a free shopping list
for matching public exploits. Secure mode answers without any component
detail. Note how the `Server` banner alone (seen in Exercise 6) already
leaks an exact version.

## Exercise 12 — Data integrity failure (A08)

Log in and open `/accounts/ledger/export`. Vulnerable mode stamps the CSV
with **unkeyed MD5**: edit the downloaded file (change an amount), recompute
`md5(file)` with any tool, and the stamp matches — tampering is undetectable.
Secure mode uses keyed **HMAC-SHA256**: the probe (PT-10) proves it cannot
forge the stamp without the server secret.

## Exercise 13 — No logging, no monitoring (A09)

Run the attacks from Exercises 1–5 again while watching the server console.
Vulnerable mode records *nothing*: failed logins, IDOR access and rejected
requests all leave no trace — an attacker can be as noisy as they like.
Secure mode writes structured `securebank.audit` events (`login_failed`,
`access_denied`, `import_rejected`); `tests/test_logging.py` pins this
white-box difference.

## Exercise 14 — SSRF (A10)

Log in as `jsmith` and use the Import page (`/import/statement`). Feed the
vulnerable build:

```
file:///C:/Windows/win.ini          (Windows)
file:///etc/hostname                (POSIX)
http://127.0.0.1:5000/login         (its own internal page)
```

The server fetches and displays it — that is server-side request forgery,
including arbitrary local file read. Secure mode enforces https + a
destination-host allowlist and rejects everything else (probe PT-11 proves
it with the lab's own login page as the fetch target).
