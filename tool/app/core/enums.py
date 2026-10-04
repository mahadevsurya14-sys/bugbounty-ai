"""
Core enumeration types for BugBounty-AI platform.
Defines modes, scope rules, finding lifecycles, and OWASP Top 10:2025 categories.
"""

from enum import Enum


class OperatingMode(str, Enum):
    """Platform operating modes defining testing constraints."""
    PASSIVE = "PASSIVE"
    ACTIVE_RECON = "ACTIVE_RECON"
    VALIDATION = "VALIDATION"
    MANUAL_ASSIST = "MANUAL_ASSIST"
    DRY_RUN = "DRY_RUN"
    LAB = "LAB"


class ScopeRuleType(str, Enum):
    """Categorization of scope boundaries."""
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    CIDR = "CIDR"
    URL = "URL"
    PORT = "PORT"
    PATH = "PATH"
    PARAMETER = "PARAMETER"
    TOOL = "TOOL"
    TEST_CATEGORY = "TEST_CATEGORY"


class ScopeEffect(str, Enum):
    """Whether a scope rule includes or excludes targets."""
    INCLUDE = "INCLUDE"
    EXCLUDE = "EXCLUDE"


class ScopeValidationStatus(str, Enum):
    """Result of a scope/policy verification check."""
    ALLOWED = "ALLOWED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    EXCLUDED = "EXCLUDED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    RATE_LIMITED = "RATE_LIMITED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    PROHIBITED_TEST = "PROHIBITED_TEST"
    PROHIBITED_TOOL = "PROHIBITED_TOOL"
    EXPIRED_WINDOW = "EXPIRED_WINDOW"


class AuditAction(str, Enum):
    """Action categories for immutable audit trails."""
    PROGRAM_CREATE = "PROGRAM_CREATE"
    PROGRAM_UPDATE = "PROGRAM_UPDATE"
    SCOPE_IMPORT = "SCOPE_IMPORT"
    SCOPE_CHECK = "SCOPE_CHECK"
    COMMAND_EXEC = "COMMAND_EXEC"
    COMMAND_BLOCKED = "COMMAND_BLOCKED"
    RECON_PASSIVE = "RECON_PASSIVE"
    RECON_ACTIVE = "RECON_ACTIVE"
    TEST_PLANNED = "TEST_PLANNED"
    TEST_APPROVED = "TEST_APPROVED"
    TEST_EXEC = "TEST_EXEC"
    EVIDENCE_COLLECT = "EVIDENCE_COLLECT"
    FINDING_CREATE = "FINDING_CREATE"
    FINDING_TRANSITION = "FINDING_TRANSITION"
    REPORT_GENERATE = "REPORT_GENERATE"


class FindingStatus(str, Enum):
    """
    Formal finding lifecycle states.
    Transition rule: Never move directly DISCOVERED -> REPORTED without human review.
    """
    DISCOVERED = "DISCOVERED"
    TRIAGE = "TRIAGE"
    SUSPECTED = "SUSPECTED"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    READY_FOR_REPORT = "READY_FOR_REPORT"
    REPORTED = "REPORTED"
    RESOLVED = "RESOLVED"


class Severity(str, Enum):
    """Standardized finding severity ratings."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """Confidence levels in a finding hypothesis or observation."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class OWASPCategory(str, Enum):
    """OWASP Top 10:2025 Test Categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
    A02_SECURITY_MISCONFIGURATION = "A02:2025 - Security Misconfiguration"
    A03_SUPPLY_CHAIN_FAILURES = "A03:2025 - Software Supply Chain Failures"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025 - Cryptographic Failures"
    A05_INJECTION = "A05:2025 - Injection"
    A06_INSECURE_DESIGN = "A06:2025 - Insecure Design"
    A07_AUTHENTICATION_FAILURES = "A07:2025 - Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2025 - Software and Data Integrity Failures"
    A09_LOGGING_ALERTING_FAILURES = "A09:2025 - Security Logging & Alerting Failures"
    A10_MISHANDLING_EXCEPTIONAL = "A10:2025 - Mishandling of Exceptional Conditions"


class AIAnalysisStatus(str, Enum):
    """Status returned by AI Verification Agent."""
    PASS = "PASS"
    SUSPECTED = "SUSPECTED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
