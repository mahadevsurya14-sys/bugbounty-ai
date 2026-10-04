"""
Unit tests for CommandRunner.
Validates argument safety, binary allowlists, dry-run simulation, and scope enforcement.
"""

import pytest
from app.core.command_runner import CommandRunner
from app.core.config import ProgramConfig, ScopeDefinitionConfig
from app.core.exceptions import CommandSafetyError, ScopeViolationError
from app.scope.engine import ScopeEngine


@pytest.fixture
def test_scope_engine():
    prog = ProgramConfig(
        program_id="test_runner_prog",
        program_name="Command Runner Test",
        scope=ScopeDefinitionConfig(
            domains=["allowed.local"],
            ips=["127.0.0.1"],
        ),
        allowed_tools=["echo", "ping"],
    )
    return ScopeEngine(prog)


def test_command_runner_disallows_unapproved_binary(test_scope_engine):
    runner = CommandRunner(scope_engine=test_scope_engine)

    with pytest.raises(CommandSafetyError):
        runner.run(["malicious_or_unknown_binary", "arg1"])


def test_command_runner_dry_run_simulation(test_scope_engine):
    runner = CommandRunner(scope_engine=test_scope_engine, dry_run=True)

    result = runner.run(["echo", "hello world"], target="allowed.local")
    assert result.dry_run is True
    assert result.exit_code == 0
    assert "[DRY_RUN]" in result.stdout


def test_command_runner_blocks_out_of_scope_target(test_scope_engine):
    runner = CommandRunner(scope_engine=test_scope_engine, dry_run=False)

    with pytest.raises(ScopeViolationError):
        runner.run(["echo", "probe"], target="unauthorized-target.com")


def test_command_runner_live_safe_execution(test_scope_engine):
    runner = CommandRunner(scope_engine=test_scope_engine, dry_run=False)

    result = runner.run(["echo", "safety_test_token"], target="127.0.0.1")
    assert result.exit_code == 0
    assert "safety_test_token" in result.stdout
