"""
CommandRunner: Safe external command execution abstraction.
Enforces:
- Binary allowlist & path verification
- Strict argument array execution (No shell=True, no unsafe string concatenation)
- Pre-execution target scope enforcement
- Rate limiter gating
- Execution timeout enforcement
- Sensitive data redaction in stdout/stderr
- Immutable audit logging
- Full dry-run mode support
"""

from dataclasses import dataclass
import shutil
import subprocess
import time
from typing import Dict, List, Optional

from app.core.audit import audit_logger
from app.core.enums import AuditAction, ScopeValidationStatus
from app.core.exceptions import CommandSafetyError, ScopeViolationError
from app.core.rate_limiter import RateLimiter
from app.core.redactor import SecurityRedactor
from app.scope.engine import ScopeEngine


@dataclass
class CommandExecutionResult:
    """Structured result of a command execution."""
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    dry_run: bool
    scope_status: ScopeValidationStatus


class CommandRunner:
    """
    Subprocess execution abstraction preventing shell injection and enforcing
    strict scope boundaries, rate limits, and security logging.
    """

    DEFAULT_ALLOWED_BINARIES = {
        "curl",
        "dig",
        "host",
        "nslookup",
        "ping",
        "whois",
        "nmap",
        "httpx",
        "dnsx",
        "subfinder",
        "ffuf",
        "katana",
        "echo",
        "pytest",
        "python3",
        "python",
    }

    def __init__(
        self,
        scope_engine: Optional[ScopeEngine] = None,
        rate_limiter: Optional[RateLimiter] = None,
        dry_run: bool = False,
        timeout: int = 30,
        allowed_binaries: Optional[set] = None,
    ):
        self.scope_engine = scope_engine
        self.rate_limiter = rate_limiter or RateLimiter()
        self.dry_run = dry_run
        self.timeout = timeout
        self.allowed_binaries = allowed_binaries or self.DEFAULT_ALLOWED_BINARIES

    def validate_binary(self, binary: str) -> str:
        """Verify binary is allowed and resolvable in PATH."""
        binary_name = binary.split("/")[-1]
        if binary_name not in self.allowed_binaries:
            raise CommandSafetyError(binary, f"Binary '{binary_name}' is not in the approved binary allowlist.")

        resolved = shutil.which(binary)
        if not resolved:
            raise CommandSafetyError(binary, f"Binary '{binary}' is not installed or not found in system PATH.")

        return resolved

    def run(
        self,
        args: List[str],
        target: Optional[str] = None,
        program_id: Optional[str] = None,
        dry_run_override: Optional[bool] = None,
        custom_timeout: Optional[int] = None,
    ) -> CommandExecutionResult:
        """
        Execute external command securely.
        1. Validate argument array.
        2. Validate binary in PATH.
        3. Enforce scope if target is supplied.
        4. Enforce rate limiting.
        5. Support Dry-Run simulation.
        6. Capture output and redact sensitive data.
        7. Audit log.
        """
        if not isinstance(args, list) or not args:
            raise CommandSafetyError(str(args), "Command arguments must be a non-empty list of strings.")

        binary = args[0]
        resolved_bin = self.validate_binary(binary)
        exec_args = [resolved_bin] + args[1:]
        is_dry_run = self.dry_run if dry_run_override is None else dry_run_override
        timeout = custom_timeout or self.timeout

        scope_status = ScopeValidationStatus.ALLOWED

        # Target Scope Check
        if target and self.scope_engine:
            val_res = self.scope_engine.validate_target(target=target, tool=binary)
            scope_status = val_res.status
            if not val_res.allowed:
                audit_logger.log(
                    target=target,
                    action=AuditAction.COMMAND_BLOCKED,
                    scope_result=scope_status,
                    program_id=program_id,
                    tool=binary,
                    result="BLOCKED",
                    details={"command": SecurityRedactor.redact_list(args), "reason": val_res.reason},
                )
                raise ScopeViolationError(target, val_res.reason)

        # Dry Run Mode
        if is_dry_run:
            cmd_str = " ".join(SecurityRedactor.redact_list(args))
            simulated_stdout = f"[DRY_RUN] Command validated and approved: {cmd_str}"
            audit_logger.log(
                target=target or "local",
                action=AuditAction.COMMAND_EXEC,
                scope_result=scope_status,
                program_id=program_id,
                tool=binary,
                result="DRY_RUN_SUCCESS",
                details={"command": SecurityRedactor.redact_list(args)},
            )
            return CommandExecutionResult(
                command=args,
                exit_code=0,
                stdout=simulated_stdout,
                stderr="",
                duration_ms=0.0,
                dry_run=True,
                scope_status=scope_status,
            )

        # Rate Limiting
        if target:
            self.rate_limiter.acquire(target, wait=True)

        start_time = time.monotonic()
        try:
            process = subprocess.run(
                exec_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,  # Strictly NO shell=True
            )
            duration = (time.monotonic() - start_time) * 1000.0

            clean_stdout = SecurityRedactor.redact_text(process.stdout)
            clean_stderr = SecurityRedactor.redact_text(process.stderr)
            exit_code = process.returncode

            audit_logger.log(
                target=target or "local",
                action=AuditAction.COMMAND_EXEC,
                scope_result=scope_status,
                program_id=program_id,
                tool=binary,
                result="SUCCESS" if exit_code == 0 else f"EXIT_{exit_code}",
                details={"command": SecurityRedactor.redact_list(args), "exit_code": exit_code},
            )

            return CommandExecutionResult(
                command=args,
                exit_code=exit_code,
                stdout=clean_stdout,
                stderr=clean_stderr,
                duration_ms=duration,
                dry_run=False,
                scope_status=scope_status,
            )
        except subprocess.TimeoutExpired:
            duration = (time.monotonic() - start_time) * 1000.0
            audit_logger.log(
                target=target or "local",
                action=AuditAction.COMMAND_EXEC,
                scope_result=scope_status,
                program_id=program_id,
                tool=binary,
                result="TIMEOUT",
                details={"command": SecurityRedactor.redact_list(args), "timeout": timeout},
            )
            return CommandExecutionResult(
                command=args,
                exit_code=124,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds.",
                duration_ms=duration,
                dry_run=False,
                scope_status=scope_status,
            )
        finally:
            if target:
                self.rate_limiter.release(target)
