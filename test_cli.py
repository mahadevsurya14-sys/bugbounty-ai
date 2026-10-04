"""
Unit tests for CLI commands using Click CliRunner.
"""

import uuid
from click.testing import CliRunner
from app.cli.main import cli


def test_cli_init():
    runner = CliRunner()
    result = runner.invoke(cli, ["init"])
    assert result.exit_code == 0
    assert "BugBounty-AI Platform Initialized Successfully" in result.output


def test_cli_program_workflow():
    runner = CliRunner()
    prog_id = f"cli_{uuid.uuid4().hex[:6]}"
    # Create program
    create_res = runner.invoke(
        cli,
        [
            "program",
            "create",
            "--id",
            prog_id,
            "--name",
            "CLI Test Program",
            "--domain",
            "*.clitest.org",
            "--exclude-domain",
            "internal.clitest.org",
        ],
    )
    assert create_res.exit_code == 0
    assert "registered successfully" in create_res.output

    # List programs
    list_res = runner.invoke(cli, ["program", "list"])
    assert list_res.exit_code == 0
    assert prog_id in list_res.output

    # Validate in-scope target
    val_res = runner.invoke(
        cli,
        ["scope", "validate", "--program", prog_id, "--target", "api.clitest.org"],
    )
    assert val_res.exit_code == 0
    assert "Target In-Scope and Authorized" in val_res.output

    # Validate excluded target (should block)
    block_res = runner.invoke(
        cli,
        ["scope", "validate", "--program", prog_id, "--target", "internal.clitest.org"],
    )
    assert block_res.exit_code == 0
    assert "Action BLOCKED by Scope Engine" in block_res.output


def test_cli_owasp_list():
    runner = CliRunner()
    res = runner.invoke(cli, ["owasp", "list"])
    assert res.exit_code == 0
    assert "A01" in res.output
    assert "Broken Access Control" in res.output
    assert "A05" in res.output
    assert "Injection" in res.output


def test_cli_lab_demo():
    runner = CliRunner()
    res = runner.invoke(cli, ["lab", "demo"])
    assert res.exit_code == 0
    assert "Localhost Demonstration Complete" in res.output
