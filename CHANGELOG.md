# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.2.0] - 2026-11-13

### Added — complete OWASP Top 10 (2021) coverage (A01–A10)
- **A06 Vulnerable & Outdated Components**: `/about` discloses exact
  framework versions and a simulated past-EOL dependency in vulnerable
  mode; secure mode answers without component detail.
  Probe PT-09 + `tests/test_component_exposure.py`.
- **A08 Software & Data Integrity Failures**: ledger export stamped with
  unkeyed MD5 (forgeable) in vulnerable mode; keyed HMAC-SHA256 in secure
  mode (`banking/integrity.py`).
  Probe PT-10 + `tests/test_integrity.py`.
- **A09 Security Logging & Monitoring Failures**: vulnerable mode logs no
  security events; secure mode emits structured `securebank.audit` events
  for failed logins, denials and rejected imports. Verified white-box
  (`tests/test_logging.py`) and reported by the research analyzer.
- **A10 Server-Side Request Forgery**: `/import/statement` fetches
  attacker-supplied URLs with any scheme (including `file://`) in
  vulnerable mode; secure mode enforces https + destination-host allowlist
  (`banking/importer.py`).
  Probe PT-11 + `tests/test_ssrf.py`.
- `tests/test_owasp_coverage.py`: meta-test asserting all ten categories
  are enumerated, confirmed in vulnerable mode and mitigated in secure mode.
- Verbose-error finding relabelled `A10-001` → `A05-002` (it belongs to
  Security Misconfiguration); A10 is now a real SSRF finding.
- Research analyzer: `analyze_logging()` posture, new endpoint counts,
  updated evidence/component maps; threat model gains actors TA-006/007/008.
- Pentest tool: 11 probes; expected result 11 vulnerable / 0 secure.

## [2.1.0] - 2026-11-13

### Changed — architecture restructure
- Layered package layout: `core/` (config, models, exceptions, helpers),
  `storage/` (SQLite), `banking/` (domain services, was `services/`),
  `webapp/` (Flask app, routes, security, server), `research/` (analyzer,
  threat model, CLI), `pentest/`, and a unified `cli/` dispatcher.
- `python -m securebank_lab` / `securebank-lab` now expose subcommands:
  `serve`, `pentest`, `research`, `threat-model`.
- `serve` finally matches the documented behaviour: it starts the lab web
  server and refuses non-loopback bind addresses (exit code 2).
- Default database location moved to `data/securebank_<mode>.db` (gitignored).

### Fixed
- `securebank-research` crashed on startup (`choices[...]` instead of
  `choices=[...]`) and when writing `--output` (double write of an
  unserialisable dataclass). Now writes one proper JSON report.
- Foreign-key introspection in the research analyzer used an invalid
  `pragma_foreign_key_list(NULL)` call; now per-table `PRAGMA`.
- Threat model: missing `return` in success-condition derivation, risk
  scoring that looked up severities by *title* instead of severity, and
  status constants that never matched (`confirmed_vulnerable` vs
  `confirmed`). Confirmed flaws now score full weight.
- `pyproject.toml`: `flask`/`werkzeug`/`markupsafe` were imported everywhere
  but never declared as dependencies; invalid ruff fields (`disable`,
  `extensions`) prevented ruff from running at all; dangling entry point
  `securebank-analyze` pointed at a non-existent module.

### Added
- `docs/`: `LAB_GUIDE.md`, `METHODOLOGY.md`, `THREAT_MODEL.md`,
  `FINDINGS.md`.
- `tests/test_research.py` (research package was previously untested) and
  CLI forwarding tests; suite now at 80 tests, coverage ~91%.
- `LICENSE` (MIT), `CHANGELOG.md`, coverage configuration.

## [2.0.0] - earlier
- Dual-mode bank (vulnerable/secure), pentest tool with loopback-only
  guard rails, research/threat-model modules (initial, partially broken).
