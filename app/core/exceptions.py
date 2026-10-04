"""
Custom exceptions for BugBounty-AI platform safety and policy enforcement.
"""

class BugBountyException(Exception):
    """Base exception for all BugBounty-AI errors."""
    pass


class ScopeViolationError(BugBountyException):
    """Raised when an operation targets an asset outside configured scope or excluded."""
    def __init__(self, target: str, reason: str):
        super().__init__(f"Scope Violation on target '{target}': {reason}")
        self.target = target
        self.reason = reason


class RateLimitExceededError(BugBountyException):
    """Raised when rate limits or concurrency thresholds are breached."""
    def __init__(self, limit: float, current: float, scope: str = "global"):
        super().__init__(f"Rate limit exceeded [{scope}]: {current:.2f} > {limit:.2f}")
        self.limit = limit
        self.current = current
        self.scope = scope


class CommandSafetyError(BugBountyException):
    """Raised when a command violates safety guidelines, shell injection checks, or binary restrictions."""
    def __init__(self, command: str, reason: str):
        super().__init__(f"Command safety check failed for '{command}': {reason}")
        self.command = command
        self.reason = reason


class ApprovalRequiredError(BugBountyException):
    """Raised when an active recon or validation action requires explicit researcher approval."""
    def __init__(self, action: str, target: str):
        super().__init__(f"Human approval required for action '{action}' on target '{target}'")
        self.action = action
        self.target = target


class ProgramNotFoundError(BugBountyException):
    """Raised when a requested program is not found in database or configuration."""
    def __init__(self, program_id: str):
        super().__init__(f"Program '{program_id}' not found.")
        self.program_id = program_id


class PolicyViolationError(BugBountyException):
    """Raised when an action violates a program's custom security testing rules or prohibited categories."""
    def __init__(self, rule: str, details: str):
        super().__init__(f"Program policy violation [{rule}]: {details}")
        self.rule = rule
        self.details = details
