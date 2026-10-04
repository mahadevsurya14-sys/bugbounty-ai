"""
External Tool Adapter Architecture.
Every external tool integration (httpx, subfinder, nmap, ffuf, katana, etc.)
inherits from ToolAdapter, ensuring mandatory scope validation, rate limiting,
installation detection, and structured output parsing.
"""

from abc import ABC, abstractmethod
import shutil
from typing import Any, Dict, List, Optional

from app.core.command_runner import CommandExecutionResult, CommandRunner
from app.core.config import ProgramConfig
from app.core.enums import ScopeValidationStatus
from app.scope.engine import ScopeEngine


class ToolAdapter(ABC):
    """Abstract base class for external CLI tool adapters."""

    def __init__(self, program: ProgramConfig, command_runner: Optional[CommandRunner] = None):
        self.program = program
        self.scope_engine = ScopeEngine(program)
        self.runner = command_runner or CommandRunner(scope_engine=self.scope_engine)

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the security tool."""
        pass

    @property
    @abstractmethod
    def binary(self) -> str:
        """Binary executable name."""
        pass

    @property
    @abstractmethod
    def purpose(self) -> str:
        """Recon or scanning purpose."""
        pass

    @property
    def passive_or_active(self) -> str:
        """Whether the tool performs passive or active queries."""
        return "active"

    @property
    def required_approval(self) -> bool:
        """Whether this tool requires researcher approval in active mode."""
        return True

    def check_installed(self) -> bool:
        """Check if the required binary is installed on the system."""
        return shutil.which(self.binary) is not None

    def get_version(self) -> str:
        """Fetch binary version."""
        if not self.check_installed():
            return "NOT_INSTALLED"
        res = self.runner.run([self.binary, "--version"], dry_run_override=False)
        return (res.stdout or res.stderr or "UNKNOWN").strip().splitlines()[0]

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Construct secure subprocess argument list for target."""
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse tool stdout into normalized dictionary records."""
        pass

    def run(self, target: str, dry_run: bool = False, **kwargs) -> CommandExecutionResult:
        """Validate target scope and execute tool."""
        if not self.check_installed():
            raise FileNotFoundError(f"Tool binary '{self.binary}' is not installed on the system.")

        args = self.build_command(target, **kwargs)
        return self.runner.run(
            args=args,
            target=target,
            program_id=self.program.program_id,
            dry_run_override=dry_run,
        )
