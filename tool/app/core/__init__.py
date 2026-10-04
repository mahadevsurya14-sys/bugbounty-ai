"""
Core modules for BugBounty-AI platform.
"""

from app.core.audit import audit_logger, AuditLogger
from app.core.command_runner import CommandExecutionResult, CommandRunner
from app.core.config import (
    ExclusionConfig,
    PlatformSettings,
    ProgramConfig,
    RateLimitConfig,
    ScopeDefinitionConfig,
    load_platform_settings,
    load_program_from_yaml,
)
from app.core.enums import (
    AIAnalysisStatus,
    AuditAction,
    ConfidenceLevel,
    FindingStatus,
    OperatingMode,
    OWASPCategory,
    ScopeEffect,
    ScopeRuleType,
    ScopeValidationStatus,
    Severity,
)
from app.core.exceptions import (
    ApprovalRequiredError,
    BugBountyException,
    CommandSafetyError,
    PolicyViolationError,
    ProgramNotFoundError,
    RateLimitExceededError,
    ScopeViolationError,
)
from app.core.rate_limiter import RateLimiter
from app.core.redactor import SecurityRedactor

__all__ = [
    "audit_logger",
    "AuditLogger",
    "CommandExecutionResult",
    "CommandRunner",
    "ExclusionConfig",
    "PlatformSettings",
    "ProgramConfig",
    "RateLimitConfig",
    "ScopeDefinitionConfig",
    "load_platform_settings",
    "load_program_from_yaml",
    "AIAnalysisStatus",
    "AuditAction",
    "ConfidenceLevel",
    "FindingStatus",
    "OperatingMode",
    "OWASPCategory",
    "ScopeEffect",
    "ScopeRuleType",
    "ScopeValidationStatus",
    "Severity",
    "ApprovalRequiredError",
    "BugBountyException",
    "CommandSafetyError",
    "PolicyViolationError",
    "ProgramNotFoundError",
    "RateLimitExceededError",
    "ScopeViolationError",
    "RateLimiter",
    "SecurityRedactor",
]
