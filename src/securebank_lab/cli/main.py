"""Unified entry point: ``securebank-lab <command>``.

Commands:

* ``serve``         - start the lab web server (loopback only)
* ``pentest``       - run the non-destructive assessment tool
* ``research``      - security-posture analysis (headless)
* ``threat-model``  - structured threat model (headless)

Examples::

    securebank-lab serve --mode vulnerable --port 5000
    securebank-lab pentest http://127.0.0.1:5000 --format json
    securebank-lab research --mode secure --output reports/posture.json
    securebank-lab threat-model --mode vulnerable
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from securebank_lab.core.config import Mode, Settings
from securebank_lab.pentest.cli import main as pentest_main
from securebank_lab.research.cli import main as research_main
from securebank_lab.research.cli import threat_model_main
from securebank_lab.webapp.server import serve_app

DEFAULT_FOREIGN_ACCOUNT = 1002


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="securebank-lab",
        description="SecureBank Lab: local cybersecurity research environment.",
    )
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser(
        "serve",
        help="Start the lab web server (loopback only)",
        description=(
            "Start the lab web server. Vulnerable mode refuses to bind to any "
            "non-loopback address."
        ),
    )
    serve.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        default="secure",
        help="Which implementation to serve (default: secure)",
    )
    serve.add_argument(
        "--host", default="127.0.0.1", help="Bind address (loopback only)"
    )
    serve.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")

    pentest = subparsers.add_parser(
        "pentest",
        help="Run the loopback-only assessment tool against a local instance",
    )
    pentest.add_argument(
        "target",
        nargs="?",
        default="http://127.0.0.1:5000",
        help="lab base URL",
    )
    pentest.add_argument("--password", help="password of user 'jsmith'")
    pentest.add_argument(
        "--foreign-account",
        type=int,
        default=DEFAULT_FOREIGN_ACCOUNT,
        help="an account id NOT owned by jsmith, used for the IDOR probe",
    )
    pentest.add_argument("--format", choices=["markdown", "json"], default="markdown")
    pentest.add_argument("--output", help="write the report to this file")
    pentest.add_argument(
        "--fail-on-vulnerable",
        action="store_true",
        help="exit 1 if any vulnerability is confirmed (for CI)",
    )

    for name, help_text in (
        ("research", "Analyze the security posture of one mode (headless)"),
        ("threat-model", "Build a structured threat model of one mode (headless)"),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("--mode", choices=["vulnerable", "secure"], required=True)
        sub.add_argument("--database", default=None, help="Override database path")
        sub.add_argument(
            "--output", default=None, help="Write JSON output to this file"
        )
        if name == "research":
            sub.add_argument(
                "--format",
                choices=["summary", "json"],
                default="summary",
                help="Stdout format",
            )

    return parser


def _run_serve(args: argparse.Namespace) -> int:
    """Start the lab server with the requested mode."""
    settings = Settings(mode=Mode(args.mode))
    return serve_app(settings, host=args.host, port=args.port)


def _run_pentest(args: argparse.Namespace) -> int:
    """Forward to the pentest CLI."""
    forward: list[str] = [args.target, "--format", args.format]
    if args.password:
        forward += ["--password", args.password]
    if args.foreign_account != DEFAULT_FOREIGN_ACCOUNT:
        forward += ["--foreign-account", str(args.foreign_account)]
    if args.output:
        forward += ["--output", args.output]
    if args.fail_on_vulnerable:
        forward += ["--fail-on-vulnerable"]
    return pentest_main(forward)


def _forward_research_args(args: argparse.Namespace) -> list[str]:
    """Build the argument list forwarded to the research CLI."""
    forward = ["--mode", args.mode]
    if args.database:
        forward += ["--database", args.database]
    if args.output:
        forward += ["--output", args.output]
    return forward


def _run_research(args: argparse.Namespace) -> int:
    """Forward to the research CLI."""
    forward = _forward_research_args(args)
    forward.append("--format")
    forward.append(args.format)
    return research_main(forward)


def _run_threat_model(args: argparse.Namespace) -> int:
    """Forward to the threat-model CLI."""
    return threat_model_main(_forward_research_args(args))


_HANDLERS = {
    "serve": _run_serve,
    "pentest": _run_pentest,
    "research": _run_research,
    "threat-model": _run_threat_model,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch to the selected subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    handler = _HANDLERS.get(args.command)
    if handler is None:  # argparse constrains the choices, belt-and-braces
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
