"""Command line interfaces for the research package.

* ``securebank-research`` - posture analysis and findings enumeration.
* ``securebank-threat-model`` - structured threat model of one mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from securebank_lab.core.config import Mode
from securebank_lab.research.analyzer import (
    run_research_analysis,
)
from securebank_lab.research.threat_model import (
    ThreatModel,
    render_text,
    run_threat_modeling,
)


def _parse_mode(value: str) -> Mode:
    """Convert a CLI string to a :class:`Mode`."""
    return Mode.VULNERABLE if value == "vulnerable" else Mode.SECURE


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the research tool."""
    parser = argparse.ArgumentParser(
        prog="securebank-research",
        description=(
            "Security-posture analysis of a SecureBank Lab mode "
            "(vulnerable or secure). Runs headlessly, no server required."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        required=True,
        help="Which bank mode to analyze",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="Override the default database path (per-mode default if omitted)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the full research report (JSON) to this file",
    )
    parser.add_argument(
        "--format",
        choices=["summary", "json"],
        default="summary",
        help="Stdout format: human summary or full JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run research analysis and print or save the report."""
    args = build_parser().parse_args(argv)
    report = run_research_analysis(
        mode=_parse_mode(args.mode),
        database_path=args.database,
        output_path=args.output,
    )

    if args.format == "json":
        print(report.to_json())
    else:
        print(report.summary)

    if args.output is not None:
        print(f"\nReport written to {args.output}", file=sys.stderr)
    return 0


def build_threat_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the threat-model tool."""
    parser = argparse.ArgumentParser(
        prog="securebank-threat-model",
        description=(
            "Structured threat model of a SecureBank Lab mode: threat actors, "
            "attack vectors, risk scores and residual risks."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "secure"],
        required=True,
        help="Which bank mode to model",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="Override the default database path",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the threat model (JSON) to this file",
    )
    return parser


def threat_model_main(argv: Sequence[str] | None = None) -> int:
    """Build the threat model and print or save it."""
    args = build_threat_parser().parse_args(argv)
    model: ThreatModel = run_threat_modeling(
        _parse_mode(args.mode),
        database_path=args.database,
    )

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(model.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        print(f"Threat model written to {args.output}", file=sys.stderr)
    print(render_text(model))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
