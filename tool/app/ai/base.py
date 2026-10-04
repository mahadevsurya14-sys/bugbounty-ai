"""
AI Agent Architecture & Hallucination Control.
Defines interfaces for:
1. Recon Analyst
2. Test Planner
3. Verification Agent
4. Reporting Agent
Includes a local deterministic rule-based implementation so the platform
operates completely offline without requiring third-party LLM API keys.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.core.enums import AIAnalysisStatus, ConfidenceLevel, OWASPCategory, Severity


@dataclass
class ReconAnalysisResult:
    """Output from Agent 1 (Recon Analyst)."""
    prioritized_targets: List[Dict[str, Any]]
    risky_areas: List[str]
    interesting_endpoints: List[str]
    technologies_of_interest: List[str]
    suggested_actions: List[str]


@dataclass
class TestPlanItem:
    """Output from Agent 2 (Test Planner)."""
    priority: str  # Priority 1, Priority 2, Priority 3
    reason: str
    target: str
    endpoint: str
    parameter: Optional[str]
    expected_observation: str
    risk: Severity
    required_approval: bool
    recommended_validation: str
    owasp_category: OWASPCategory


@dataclass
class VerificationResult:
    """Output from Agent 3 (Verification Agent)."""
    status: AIAnalysisStatus
    evidence_ids: List[str]
    confidence: ConfidenceLevel
    owasp_category: OWASPCategory
    cwe_id: str
    impact: str
    reasoning: str
    is_hallucination_safe: bool = True


@dataclass
class ReportDraft:
    """Output from Agent 4 (Reporting Agent)."""
    title: str
    summary: str
    asset: str
    endpoint: str
    severity: Severity
    confidence: ConfidenceLevel
    owasp_category: OWASPCategory
    cwe_id: str
    description: str
    preconditions: str
    steps_to_reproduce: List[str]
    observed_result: str
    expected_result: str
    evidence_ids: List[str]
    business_impact: str
    technical_impact: str
    remediation: str
    references: List[str]
    status_classification: str  # Observed / Inferred / Suspected / Verified


class BaseAIEngine(ABC):
    """Abstract interface for AI intelligence providers."""

    @abstractmethod
    def analyze_recon(self, attack_surface_data: Dict[str, Any]) -> ReconAnalysisResult:
        pass

    @abstractmethod
    def plan_tests(self, attack_surface_data: Dict[str, Any]) -> List[TestPlanItem]:
        pass

    @abstractmethod
    def verify_finding(self, baseline: Dict[str, Any], test_data: Dict[str, Any], evidence_id: str) -> VerificationResult:
        pass

    @abstractmethod
    def generate_report(self, finding_data: Dict[str, Any], evidence_items: List[Dict[str, Any]]) -> ReportDraft:
        pass


class LocalRuleBasedAIEngine(BaseAIEngine):
    """
    Local deterministic AI engine.
    Ensures zero remote dependency, strict evidence referencing, and no hallucinations.
    """

    def analyze_recon(self, attack_surface_data: Dict[str, Any]) -> ReconAnalysisResult:
        endpoints = attack_surface_data.get("endpoints", [])
        interesting = []
        risky = []

        for ep in endpoints:
            path = ep.get("path", "")
            if any(k in path.lower() for k in ["admin", "api", "auth", "login", "v1", "v2", "debug", "upload"]):
                interesting.append(path)
                risky.append(f"High-exposure endpoint discovered: {path}")

        return ReconAnalysisResult(
            prioritized_targets=[{"endpoint": ep, "priority": "HIGH"} for ep in interesting],
            risky_areas=risky if risky else ["Standard attack surface, no high-risk endpoints detected yet."],
            interesting_endpoints=interesting,
            technologies_of_interest=attack_surface_data.get("technologies", []),
            suggested_actions=["Baseline HTTP fingerprinting", "Inspect API parameter schemas", "Map authentication boundaries"],
        )

    def plan_tests(self, attack_surface_data: Dict[str, Any]) -> List[TestPlanItem]:
        items = []
        endpoints = attack_surface_data.get("endpoints", [])
        for ep in endpoints:
            path = ep.get("path", "/")
            items.append(
                TestPlanItem(
                    priority="Priority 1" if "admin" in path or "api" in path else "Priority 2",
                    reason=f"Exposed route {path} requires authorization and security configuration review.",
                    target=attack_surface_data.get("target", "localhost"),
                    endpoint=path,
                    parameter=None,
                    expected_observation="Status code parity and absence of debug traces or missing security controls.",
                    risk=Severity.MEDIUM,
                    required_approval=False,
                    recommended_validation="Non-destructive canary request and response header inspection.",
                    owasp_category=OWASPCategory.A02_SECURITY_MISCONFIGURATION,
                )
            )
        return items

    def verify_finding(self, baseline: Dict[str, Any], test_data: Dict[str, Any], evidence_id: str) -> VerificationResult:
        # Strict rule: NEVER verify without real evidence_id
        if not evidence_id:
            return VerificationResult(
                status=AIAnalysisStatus.NEEDS_MANUAL_REVIEW,
                evidence_ids=[],
                confidence=ConfidenceLevel.LOW,
                owasp_category=OWASPCategory.A02_SECURITY_MISCONFIGURATION,
                cwe_id="CWE-699",
                impact="Unverified: Missing primary evidence artifact.",
                reasoning="Safety policy blocks verification when evidence ID is absent.",
            )

        status_baseline = baseline.get("status_code", 200)
        status_test = test_data.get("status_code", 200)
        diff_observed = status_baseline != status_test or "error" in str(test_data.get("body", "")).lower()

        status = AIAnalysisStatus.SUSPECTED if diff_observed else AIAnalysisStatus.PASS
        return VerificationResult(
            status=status,
            evidence_ids=[evidence_id],
            confidence=ConfidenceLevel.MEDIUM if diff_observed else ConfidenceLevel.LOW,
            owasp_category=OWASPCategory.A02_SECURITY_MISCONFIGURATION,
            cwe_id="CWE-16",
            impact="Behavioral differential detected between baseline and canary request.",
            reasoning=f"Baseline returned HTTP {status_baseline}, canary test returned HTTP {status_test}. Backed by Evidence [{evidence_id}].",
        )

    def generate_report(self, finding_data: Dict[str, Any], evidence_items: List[Dict[str, Any]]) -> ReportDraft:
        ev_ids = [e.get("id", "EV-UNKNOWN") for e in evidence_items]
        return ReportDraft(
            title=finding_data.get("title", "Security Observation"),
            summary=finding_data.get("description", "A security anomaly was identified during authorized testing."),
            asset=finding_data.get("affected_asset", "Target Asset"),
            endpoint=finding_data.get("endpoint", "/"),
            severity=finding_data.get("severity", Severity.INFO),
            confidence=finding_data.get("confidence", ConfidenceLevel.MEDIUM),
            owasp_category=finding_data.get("owasp_category", OWASPCategory.A02_SECURITY_MISCONFIGURATION),
            cwe_id=finding_data.get("cwe_id", "CWE-200"),
            description=finding_data.get("description", ""),
            preconditions="Authorized access to target scope.",
            steps_to_reproduce=[
                "1. Send baseline request to target endpoint.",
                "2. Observe server response headers and status.",
                "3. Validate against configured security baseline.",
            ],
            observed_result="Server response differed from hardened baseline specification.",
            expected_result="Strict security headers and proper boundary access enforcement.",
            evidence_ids=ev_ids,
            business_impact=finding_data.get("business_impact", "Potential disclosure of architectural metadata."),
            technical_impact=finding_data.get("technical_impact", "Information disclosure via server response."),
            remediation=finding_data.get("remediation", "Implement standard defensive configuration and rate limiting."),
            references=["https://owasp.org/Top10/"],
            status_classification="Suspected",
        )
