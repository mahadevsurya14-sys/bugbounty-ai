"""
Unit tests for MAHADU branding module and CLI about/version commands.
"""

from io import StringIO
from click.testing import CliRunner
from rich.console import Console

from app.core.banner import (
    BANNER_ART,
    __author__,
    __brand__,
    __project__,
    __version__,
    branded_header,
    show_about,
    show_banner,
    show_footer,
    show_status,
    show_version,
    show_welcome,
)
from app.cli.main import cli


def _capture_rich(func, *args):
    """Capture Rich console output from a function."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120)
    # Temporarily patch the module-level console
    import app.core.banner as banner_mod
    original_console = banner_mod.console
    banner_mod.console = console
    try:
        func(*args)
    finally:
        banner_mod.console = original_console
    return buf.getvalue()


def test_banner_contains_mahadu_art():
    assert "MAHADU" in BANNER_ART or "███" in BANNER_ART


def test_brand_constants():
    assert __brand__ == "MAHADU"
    assert __project__ == "BugBounty-AI"
    assert __author__ == "Mahadev Suryavanshi"
    assert __version__ == "0.1.0"


def test_branded_header():
    assert branded_header("Recon") == "MAHADU // Recon"
    assert branded_header("Scope") == "MAHADU // Scope"
    assert branded_header("OWASP") == "MAHADU // OWASP"


def test_show_banner_renders():
    output = _capture_rich(show_banner)
    assert "MAHADU" in output
    assert "BugBounty-AI" in output


def test_show_status_renders():
    output = _capture_rich(show_status)
    assert "READY" in output
    assert "AUTHORIZED SECURITY RESEARCH ONLY" in output


def test_show_footer_renders():
    output = _capture_rich(show_footer)
    assert "MAHADU" in output
    assert "v0.1.0" in output


def test_show_about_renders():
    output = _capture_rich(show_about)
    assert "Mahadev Suryavanshi" in output
    assert "BugBounty-AI" in output
    assert "Apache-2.0" in output


def test_show_version_renders():
    output = _capture_rich(show_version)
    assert "MAHADU" in output
    assert "0.1.0" in output


def test_show_welcome_renders():
    output = _capture_rich(show_welcome)
    assert "MAHADU" in output
    assert "READY" in output


# ==============================================================================
# CLI command tests
# ==============================================================================
def test_cli_about_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["about"])
    assert result.exit_code == 0
    assert "MAHADU" in result.output
    assert "Mahadev Suryavanshi" in result.output


def test_cli_version_command():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "MAHADU" in result.output
    assert "0.1.0" in result.output


def test_cli_bare_invocation_shows_welcome():
    runner = CliRunner()
    result = runner.invoke(cli, [])
    assert result.exit_code == 0
    assert "MAHADU" in result.output


def test_cli_help_shows_branding():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "MAHADU" in result.output
    assert "BugBounty-AI" in result.output
