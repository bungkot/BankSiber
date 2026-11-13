"""The CLI and server must refuse to expose vulnerable mode to a network."""

from __future__ import annotations

import pytest

from securebank_lab.cli.main import main
from securebank_lab.core.netutil import is_loopback
from securebank_lab.webapp.server import QuietBannerHandler


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("localhost", True),
        ("::1", True),
        ("0.0.0.0", False),
        ("192.168.1.10", False),
        ("example.com", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert is_loopback(host) is expected


def test_vulnerable_mode_refuses_public_bind() -> None:
    assert main(["serve", "--mode", "vulnerable", "--host", "0.0.0.0"]) == 2


def test_secure_mode_refuses_public_bind() -> None:
    assert main(["serve", "--mode", "secure", "--host", "192.168.1.10"]) == 2


def test_no_command_prints_help() -> None:
    assert main([]) == 0


def test_server_banner_hides_versions() -> None:
    handler = QuietBannerHandler.__new__(QuietBannerHandler)
    assert handler.version_string() == "SecureBank"


def test_cli_research_command_writes_report(tmp_path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "posture.json"
    assert main(["research", "--mode", "secure", "--output", str(out)]) == 0
    assert out.exists()


def test_cli_threat_model_command(tmp_path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "tm.json"
    assert main(["threat-model", "--mode", "vulnerable", "--output", str(out)]) == 0
    assert out.exists()


def test_cli_pentest_refuses_unreachable_target() -> None:
    # No lab server is running on this port; the CLI must exit with 2.
    assert main(["pentest", "http://127.0.0.1:59999"]) == 2
