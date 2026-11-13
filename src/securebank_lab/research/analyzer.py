"""Research-oriented analytics for the SecureBank Lab.

Provides attack-surface analysis, security-posture assessment and structured
vulnerability enumeration that operate headlessly on either implementation.
This module is deliberately independent of the web layer so it can run in
CI, in scripts or from the REPL.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securebank_lab.banking.base import AccountService
from securebank_lab.banking.secure import SecureAccountService
from securebank_lab.banking.vulnerable import VulnerableAccountService
from securebank_lab.core.config import Mode, Settings
from securebank_lab.storage.database import connect, init_db

logger = logging.getLogger("securebank.research")

_SEVERITY_SCORE = {"Critical": 9.0, "High": 7.0, "Medium": 5.0, "Low": 3.0}


@dataclass(frozen=True, slots=True)
class VulnerabilityFinding:
    """A single identified vulnerability or security-control result."""

    id: str
    title: str
    category: str
    severity: str
    status: str  # "confirmed" (flaw present) or "mitigated" (control in place)
    evidence: str
    recommendation: str
    affected_component: str
    mode: Mode
    timestamp: str


@dataclass(frozen=True, slots=True)
class AttackSurface:
    """Summary of the attack surface for a given mode."""

    mode: Mode
    total_services: int
    total_endpoints: int
    vulnerable_components: int
    authenticated_endpoints: int
    unauthenticated_endpoints: int
    database_exposures: list[str]
    session_management: dict[str, Any]
    cryptographic_status: dict[str, Any]
    headers: dict[str, Any]
    logging_monitoring: dict[str, Any]
    generated_at: str


@dataclass(frozen=True, slots=True)
class ResearchReport:
    """A comprehensive research report generated from analysis."""

    target_url: str
    mode: Mode
    generated_at: datetime
    vulnerability_findings: tuple[VulnerabilityFinding, ...]
    attack_surface: AttackSurface
    summary: str
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the report."""
        return {
            "target_url": self.target_url,
            "mode": self.mode.value,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.summary,
            "attack_surface": asdict(self.attack_surface),
            "findings": [asdict(f) for f in self.vulnerability_findings],
            "recommendations": list(self.recommendations),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise the full report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


class ResearchAnalyzer:
    """Analyse a SecureBank Lab instance for research and threat modelling."""

    def __init__(
        self,
        mode: Mode,
        database_path: Path | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.mode = mode
        self.settings = settings or Settings(mode=mode, database_path=database_path)
        self._conn: sqlite3.Connection | None = None
        self._service: AccountService | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        """Lazily opened connection to the mode's database."""
        if self._conn is None:
            self._conn = connect(self.settings.resolved_database_path)
        return self._conn

    @property
    def service(self) -> AccountService:
        """The service implementation matching the analysed mode."""
        if self._service is None:
            self._service = (
                SecureAccountService(self.conn)
                if self.mode is Mode.SECURE
                else VulnerableAccountService(self.conn)
            )
        return self._service

    def analyze_database_schema(self) -> dict[str, Any]:
        """Return metadata about the database schema and data state."""
        schema: dict[str, Any] = {"tables": [], "row_counts": {}, "foreign_keys": []}
        for row in self.conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ):
            name = str(row["name"])
            schema["tables"].append({"name": name, "sql": row["sql"]})
            count = self.conn.execute(
                f"SELECT COUNT(*) FROM {name}"  # noqa: S608 - name from sqlite_master
            ).fetchone()[0]
            schema["row_counts"][name] = int(count)
            # pragma foreign_key_list requires the table name as its argument.
            for fk in self.conn.execute(
                f'PRAGMA foreign_key_list("{name}")',  # name comes from sqlite_master
            ):
                schema["foreign_keys"].append(
                    {
                        "fk": f"{name}.{fk['from']}",
                        "references": f"{fk['table']}.{fk['to']}",
                    }
                )
        return schema

    def analyze_authentication(self) -> dict[str, Any]:
        """Authentication-flow posture of the analysed mode."""
        vulnerable = self.mode is Mode.VULNERABLE
        results: dict[str, Any] = {
            "password_storage": "plaintext" if vulnerable else "hashed",
            "lockout_mechanism": "disabled" if vulnerable else "enabled",
            "max_failures_before_lockout": 0 if vulnerable else 5,
            "lockout_duration_seconds": 0 if vulnerable else 15 * 60,
            "user_enumeration_resistant": not vulnerable,
        }
        row = self.conn.execute(
            "SELECT password FROM users WHERE username = ?", ("jsmith",)
        ).fetchone()
        if row:
            stored = str(row["password"])
            if stored.startswith(("scrypt:", "pbkdf2:", "argon2")):
                results["password_hash_algo"] = stored.split("$")[1]
            else:
                results["password_hash_algo"] = "none/plaintext"  # noqa: S105
        return results

    def analyze_authorization(self) -> dict[str, Any]:
        """Object-level authorisation posture of the analysed mode."""
        vulnerable = self.mode is Mode.VULNERABLE
        return {
            "idor_protection": "none" if vulnerable else "enforced",
            "owner_check_in_get_transactions": "absent" if vulnerable else "present",
            "uniform_404_for_foreign": "no" if vulnerable else "yes",
        }

    def analyze_cryptography(self) -> dict[str, Any]:
        """Cryptographic posture of the analysed mode."""
        results: dict[str, Any] = {
            "passwords_hashed": self.mode is Mode.SECURE,
            "hash_algorithm": "none",
            "secret_key_weak": self.mode is Mode.VULNERABLE,
            "transport_tls_required": self.mode is Mode.SECURE,
        }
        if self.mode is Mode.SECURE:
            row = self.conn.execute(
                "SELECT password FROM users WHERE username = ?", ("jsmith",)
            ).fetchone()
            if row:
                stored = str(row["password"])
                if stored.startswith(("scrypt:", "pbkdf2:", "argon2")):
                    results["hash_algorithm"] = stored.split("$")[1]
        return results

    def analyze_session_management(self) -> dict[str, Any]:
        """Session cookie and CSRF-protection posture."""
        vulnerable = self.mode is Mode.VULNERABLE
        return {
            "csrf_protection": "disabled" if vulnerable else "enabled",
            "http_only_cookies": not vulnerable,
            "same_site_cookies": not vulnerable,
            "secure_cookies": self.mode is Mode.SECURE and self.settings.cookie_secure,
        }

    def analyze_security_headers(self) -> dict[str, Any]:
        """HTTP security headers present or absent in each mode."""
        vulnerable = self.mode is Mode.VULNERABLE
        suffix = "absent" if vulnerable else "present"
        return {
            "content_security_policy": suffix,
            "x_content_type_options": suffix,
            "x_frame_options": suffix,
            "referrer_policy": suffix,
            "cache_control": suffix,
        }

    def analyze_logging(self) -> dict[str, Any]:
        """Security logging and monitoring posture (OWASP A09)."""
        vulnerable = self.mode is Mode.VULNERABLE
        return {
            "security_event_logging": "disabled" if vulnerable else "enabled",
            "failed_login_logged": not vulnerable,
            "access_denials_logged": not vulnerable,
            "alerting": "none" if vulnerable else "audit logger",
            "log_integrity_protection": "none",
        }

    def enumerate_vulnerabilities(self) -> tuple[VulnerabilityFinding, ...]:
        """Structured enumeration mapped to the OWASP Top 10 categories."""
        now = datetime.now(timezone.utc).isoformat()
        findings: list[VulnerabilityFinding] = []
        vulnerable = self.mode is Mode.VULNERABLE

        def finding(
            id_: str,
            title: str,
            category: str,
            severity: str,
            evidence: str,
            recommendation: str,
            component: str,
        ) -> None:
            findings.append(
                VulnerabilityFinding(
                    id=id_,
                    title=title,
                    category=category,
                    severity=severity,
                    status="confirmed" if vulnerable else "mitigated",
                    evidence=evidence if vulnerable else _mitigated_evidence[id_],
                    recommendation=recommendation,
                    affected_component=_mitigated_component[id_]
                    if not vulnerable
                    else component,
                    mode=self.mode,
                    timestamp=now,
                )
            )

        # A01:2021 - Broken Access Control (IDOR)
        finding(
            "A01-001",
            "Insecure Direct Object Reference - Transaction Access",
            "Broken Access Control",
            "High",
            "Any authenticated user can access any account's transactions via "
            "/accounts/{id}/transactions without owner verification",
            "Implement object-level authorisation: verify the requester owns "
            "the target account before returning data",
            "banking/vulnerable.py:get_transactions",
        )

        # A02:2021 - Cryptographic Failures
        finding(
            "A02-001",
            "Plaintext Password Storage",
            "Cryptographic Failures",
            "Critical",
            "User passwords stored and compared in plaintext; authentication "
            "query uses literal string concatenation",
            "Hash all passwords with an adaptive one-way function "
            "(scrypt/pbkdf2/argon2); never compare plaintext",
            "banking/vulnerable.py:authenticate; storage/database.py",
        )

        # A03:2021 - Injection (SQL injection in search and login)
        finding(
            "A03-001",
            "SQL Injection in Transaction Search",
            "Injection",
            "Critical",
            "Search term concatenated directly into the SQL query via an "
            "f-string LIKE clause; UNION-based injection is feasible",
            "Use parameterised queries with bound parameters; escape LIKE wildcards",
            "banking/vulnerable.py:search_transactions",
        )

        # A04:2021 - Insecure Design
        finding(
            "A04-001",
            "Insecure Design - Negative/unlimited Transfers",
            "Insecure Design",
            "High",
            "No validation of transfer amounts; negative amounts reverse the "
            "transfer direction; no per-transfer limit",
            "Validate input, enforce amount limits and business rules at the "
            "service layer; use atomic SQL with balance checks",
            "banking/vulnerable.py:transfer",
        )

        # A05:2021 - Security Misconfiguration
        finding(
            "A05-001",
            "Weak Session Secret Key",
            "Security Misconfiguration",
            "High",
            "SECRET_KEY set to a hardcoded guessable value; session cookies "
            "are forgeable",
            "Use a cryptographically random secret key; rotate regularly; "
            "never hardcode secrets in source",
            "webapp/app.py:_WEAK_SECRET; core/config.py",
        )

        # A07:2021 - Identification and Authentication Failures
        finding(
            "A07-001",
            "No Account Lockout or Rate Limiting",
            "Authentication Failures",
            "High",
            "No limit on failed login attempts; credentials can be tried "
            "indefinitely; published default credentials accepted",
            "Implement progressive lockout with increasing delays; add rate "
            "limiting; force a password change after lockout",
            "banking/vulnerable.py:authenticate; storage/database.py",
        )

        # A05:2021 - Security Misconfiguration (verbose errors)
        finding(
            "A05-002",
            "Error Detail Disclosure",
            "Security Misconfiguration",
            "Medium",
            "Unhandled exceptions return the full Python stack trace to the client",
            "Return generic error messages to clients; log full details "
            "server-side; include a request id for correlation",
            "webapp/app.py:handle_unexpected",
        )

        # A06:2021 - Vulnerable and Outdated Components
        finding(
            "A06-001",
            "Component Version Disclosure and Outdated Dependency",
            "Vulnerable and Outdated Components",
            "Medium",
            "Anonymous visitors can read exact framework versions and a "
            "pinned dependency that is past end of life via /about; the "
            "export path also relies on the deprecated MD5 primitive",
            "Inventory dependencies (SBOM), remove version disclosure, "
            "upgrade or replace anything past end of life",
            "webapp/routes.py:about; banking/integrity.py",
        )

        # A08:2021 - Software and Data Integrity Failures
        finding(
            "A08-001",
            "Forgeable Ledger Export Integrity Stamp",
            "Software and Data Integrity Failures",
            "High",
            "Ledger exports are stamped with unkeyed MD5; anyone can edit "
            "the export and recompute the stamp, so tampering is undetectable",
            "Sign exports with keyed HMAC-SHA256 using a server-side secret; "
            "verify the signature on import",
            "banking/integrity.py:LegacyIntegrityStamper; "
            "webapp/routes.py:ledger_export",
        )

        # A09:2021 - Security Logging and Monitoring Failures
        finding(
            "A09-001",
            "No Security Event Logging or Monitoring",
            "Security Logging and Monitoring Failures",
            "High",
            "Failed logins, denied access attempts and rejected imports are "
            "not logged anywhere; there is no alerting, so an ongoing attack "
            "is invisible",
            "Log every security-relevant event (auth failures, denials, "
            "validation rejects) with structured fields; route to central "
            "monitoring with alerting",
            "banking/vulnerable.py; webapp/routes.py:import_statement",
        )

        # A10:2021 - Server-Side Request Forgery
        finding(
            "A10-001",
            "Server-Side Request Forgery via Statement Import",
            "Server-Side Request Forgery",
            "High",
            "The statement importer fetches any URL supplied by the user, "
            "including file:// and internal http:// resources, with no "
            "scheme or host validation",
            "Allowlist the URL scheme and destination host; deny internal "
            "and link-local addresses; cap response size",
            "banking/importer.py:VulnerableStatementImporter; "
            "webapp/routes.py:import_statement",
        )

        return tuple(findings)

    def generate_attack_surface_report(self) -> AttackSurface:
        """Generate a comprehensive attack-surface summary."""
        if self.mode is Mode.VULNERABLE:
            database_exposures = [
                "plaintext passwords in users table",
                "no balance constraint on accounts",
            ]
        else:
            database_exposures = [
                "hashed passwords (scrypt)",
                "balance >= 0 constraint enforced",
            ]

        vulnerable = self.mode is Mode.VULNERABLE
        findings = self.enumerate_vulnerabilities()
        components = {f.affected_component for f in findings if f.status == "confirmed"}

        return AttackSurface(
            mode=self.mode,
            total_services=8,  # banking ops + export, import, component info
            # /login, /, /accounts/<id>/transactions, /search, /transfer,
            # /about, /accounts/ledger/export, /import/statement
            total_endpoints=8,
            vulnerable_components=len(components) if vulnerable else 0,
            authenticated_endpoints=6,
            unauthenticated_endpoints=2,
            database_exposures=database_exposures,
            session_management=self.analyze_session_management(),
            cryptographic_status=self.analyze_cryptography(),
            headers=self.analyze_security_headers(),
            logging_monitoring=self.analyze_logging(),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_research_report(self) -> ResearchReport:
        """Produce a full research report combining all analysis data."""
        findings = self.enumerate_vulnerabilities()
        attack_surface = self.generate_attack_surface_report()

        confirmed = sum(1 for f in findings if f.status == "confirmed")
        mitigated = sum(1 for f in findings if f.status == "mitigated")

        summary_parts = [
            f"SecureBank Lab Research Analysis - Mode: {self.mode.value}",
            f"Total findings: {len(findings)}",
            f"  - Confirmed vulnerabilities: {confirmed}",
            f"  - Mitigated (fixed) vulnerabilities: {mitigated}",
        ]
        if self.mode is Mode.VULNERABLE:
            summary_parts.append(
                "This mode is intentionally designed with documented weaknesses "
                "for research and education. All findings are expected."
            )
        else:
            summary_parts.append(
                "This mode implements security controls addressing the documented "
                "vulnerabilities. Residual risk should be assessed per threat model."
            )

        recommendations: list[str] = []
        for f in findings:
            if f.recommendation not in recommendations:
                recommendations.append(f.recommendation)

        return ResearchReport(
            target_url=f"http://127.0.0.1:5000 (mode={self.mode.value})",
            mode=self.mode,
            generated_at=datetime.now(timezone.utc),
            vulnerability_findings=findings,
            attack_surface=attack_surface,
            summary="\n".join(summary_parts),
            recommendations=recommendations,
        )

    def to_json(self) -> str:
        """Serialise a read-only analysis snapshot to JSON."""
        data: dict[str, Any] = {
            "mode": self.mode.value,
            "database_path": str(self.settings.resolved_database_path),
            "schema": self.analyze_database_schema(),
            "authentication": self.analyze_authentication(),
            "cryptography": self.analyze_cryptography(),
            "session_management": self.analyze_session_management(),
            "security_headers": self.analyze_security_headers(),
            "logging_monitoring": self.analyze_logging(),
            "authorization": self.analyze_authorization(),
            "findings": [asdict(f) for f in self.enumerate_vulnerabilities()],
        }
        return json.dumps(data, indent=2, default=str)


# Per-finding evidence shown when the same item is analysed in secure mode.
_mitigated_evidence = {
    "A01-001": "Server enforces an owner check; foreign accounts return a uniform 404.",
    "A02-001": (
        "Passwords stored as salted scrypt hashes; authentication uses a "
        "constant-time hash check."
    ),
    "A03-001": (
        "Bound parameters used; LIKE wildcards escaped with an ESCAPE clause; "
        "search length limited."
    ),
    "A04-001": (
        "Amount validated (positive, capped); atomic SQL with balance check "
        "prevents negative balances; source ownership verified."
    ),
    "A05-001": (
        "SECRET_KEY generated randomly via secrets.token_hex(32) unless "
        "explicitly overridden."
    ),
    "A05-002": "Generic error page with an error id; details logged server-side only.",
    "A06-001": (
        "No component version details are disclosed; dependencies are "
        "inventoried and the deprecated MD5 primitive is retired."
    ),
    "A07-001": (
        "Progressive lockout: 5 failed attempts trigger a 15-minute lockout; "
        "audit log entries generated."
    ),
    "A08-001": (
        "Exports are stamped with keyed HMAC-SHA256; tampering without the "
        "server secret is detectable."
    ),
    "A09-001": (
        "Every security-relevant event (login failures, denials, rejected "
        "imports) is written to a structured audit log."
    ),
    "A10-001": (
        "Importer enforces an https-only scheme and a destination-host "
        "allowlist; everything else fails closed."
    ),
}

_mitigated_component = {
    "A01-001": "banking/secure.py:get_transactions",
    "A02-001": "banking/secure.py:authenticate; storage/database.py:init_db",
    "A03-001": "banking/secure.py:search_transactions",
    "A04-001": "banking/secure.py:transfer; banking/secure.py:parse_amount_cents",
    "A05-001": "webapp/app.py; core/config.py",
    "A05-002": "webapp/app.py:handle_unexpected",
    "A06-001": "webapp/routes.py:about; banking/integrity.py:HmacIntegrityStamper",
    "A07-001": "banking/secure.py:authenticate",
    "A08-001": "banking/integrity.py:HmacIntegrityStamper",
    "A09-001": "webapp/routes.py:import_statement; banking/secure.py",
    "A10-001": "banking/importer.py:SecureStatementImporter",
}


def run_research_analysis(
    mode: Mode,
    database_path: Path | None = None,
    output_path: Path | None = None,
) -> ResearchReport:
    """Convenience function: create an analyzer and produce a full report."""
    analyzer = ResearchAnalyzer(mode, database_path=database_path)
    init_db(analyzer.settings.resolved_database_path, mode)
    report = analyzer.generate_research_report()
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report.to_json(), encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SecureBank Lab research analysis tool"
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        required=True,
        help="Which mode to analyze",
    )
    parser.add_argument("--database", type=Path, help="Override database path")
    parser.add_argument("--output", type=Path, help="Write JSON report to this file")
    args = parser.parse_args()

    mode = Mode.VULNERABLE if args.mode == "vulnerable" else Mode.SECURE
    report = run_research_analysis(
        mode, database_path=args.database, output_path=args.output
    )
    print(report.summary)
    confirmed = sum(1 for f in report.vulnerability_findings if f.status == "confirmed")
    mitigated = sum(1 for f in report.vulnerability_findings if f.status == "mitigated")
    print(
        f"\nFindings: {len(report.vulnerability_findings)} total "
        f"(confirmed={confirmed}, mitigated={mitigated})"
    )
    for f in report.vulnerability_findings:
        print(f"  [{f.severity}] {f.id}: {f.title} ({f.status})")
