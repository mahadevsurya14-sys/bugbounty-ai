"""
OWASP Top 10:2025 Test Registry and TestPlugin Specification.
Provides structured metadata and plugin abstractions for safe, authorized security checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.enums import ConfidenceLevel, OWASPCategory, Severity


@dataclass
class TestResult:
    """Outcome of an executed security test."""
    test_id: str
    target: str
    vulnerable: bool
    status: str
    severity: Severity
    confidence: ConfidenceLevel
    title: str
    description: str
    evidence_data: Dict[str, Any]
    owasp_category: OWASPCategory
    cwe_id: Optional[str] = None
    baseline_diff: Optional[Dict[str, Any]] = None


class TestPlugin(ABC):
    """Abstract base class for all OWASP Top 10:2025 security tests."""

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique test identifier (e.g., TEST-A02-001)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable test name."""
        pass

    @property
    @abstractmethod
    def category(self) -> OWASPCategory:
        """OWASP Top 10:2025 category."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Test explanation and rationale."""
        pass

    @property
    def prerequisites(self) -> List[str]:
        return []

    @property
    def required_auth_state(self) -> str:
        return "unauthenticated"

    @property
    def safe_mode(self) -> bool:
        """Safe non-destructive canary testing."""
        return True

    @property
    def approval_required(self) -> bool:
        """Requires explicit researcher confirmation before active run."""
        return False

    @property
    def risk_level(self) -> Severity:
        return Severity.LOW

    @abstractmethod
    def execute(self, target: str, context: Optional[Dict[str, Any]] = None) -> TestResult:
        """Execute safe baseline comparison or non-destructive check."""
        pass

    def map_owasp(self) -> OWASPCategory:
        return self.category

    @abstractmethod
    def map_cwe(self) -> str:
        """Associated Common Weakness Enumeration ID (e.g., CWE-200)."""
        pass


class OWASPTestRegistry:
    """Registry managing available OWASP Top 10:2025 test plugins."""

    def __init__(self):
        self._tests: Dict[str, TestPlugin] = {}

    def register(self, test: TestPlugin):
        self._tests[test.id] = test

    def get_test(self, test_id: str) -> Optional[TestPlugin]:
        return self._tests.get(test_id)

    def list_tests(self, category: Optional[OWASPCategory] = None) -> List[TestPlugin]:
        tests = list(self._tests.values())
        if category:
            tests = [t for t in tests if t.category == category]
        return tests


# Global registry
owasp_registry = OWASPTestRegistry()
