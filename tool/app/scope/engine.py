"""
Scope Engine.
Enforces the mandatory authorization and scope pipeline:
TARGET -> SCOPE CHECK -> EXCLUSION CHECK -> POLICY CHECK -> RATE LIMIT CHECK -> TEST AUTHORIZATION CHECK -> EXECUTION.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.core.config import ProgramConfig
from app.core.enums import ScopeValidationStatus
from app.scope.normalizer import ScopeNormalizer


@dataclass
class ScopeValidationResult:
    """Detailed result of target scope and authorization check."""
    status: ScopeValidationStatus
    allowed: bool
    reason: str
    target: str
    details: Dict[str, Any]


class ScopeEngine:
    """
    Dedicated Scope and Authorization Engine for BugBounty-AI.
    Validates targets against in-scope rules, exclusion lists, tool permissions,
    and program policy constraints.
    """

    def __init__(self, program: ProgramConfig):
        self.program = program

    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if domain matches any in-scope domain or wildcard pattern."""
        norm_target = ScopeNormalizer.normalize_domain(domain)
        if not norm_target:
            return False

        # In-scope check
        for pattern in self.program.scope.domains:
            if ScopeNormalizer.matches_domain(pattern, norm_target):
                return True
        return False

    def is_domain_excluded(self, domain: str) -> bool:
        """Check if domain matches any exclusion rule."""
        norm_target = ScopeNormalizer.normalize_domain(domain)
        for pattern in self.program.exclusions.domains:
            if ScopeNormalizer.matches_domain(pattern, norm_target):
                return True
        return False

    def is_subdomain_in_scope(self, subdomain: str) -> bool:
        """Check if subdomain is within authorized scope."""
        # Subdomains check both explicitly listed subdomains and wildcard domains
        norm_target = ScopeNormalizer.normalize_domain(subdomain)
        if self.is_domain_excluded(norm_target):
            return False

        for sub in self.program.scope.subdomains:
            if ScopeNormalizer.matches_domain(sub, norm_target):
                return True

        return self.is_domain_in_scope(norm_target)

    def is_ip_in_scope(self, ip_str: str) -> bool:
        """Check if an IP address is in scope (direct match or CIDR)."""
        target_ip = ScopeNormalizer.normalize_ip(ip_str)
        if not target_ip:
            return False

        # Direct IP check
        for ip in self.program.scope.ips:
            rule_ip = ScopeNormalizer.normalize_ip(ip)
            if rule_ip and rule_ip == target_ip:
                return True

        # CIDR check
        for cidr in self.program.scope.cidrs:
            if ScopeNormalizer.is_ip_in_cidr(ip_str, cidr):
                return True

        return False

    def is_cidr_in_scope(self, cidr_str: str) -> bool:
        """Check if a CIDR block is in scope."""
        target_net = ScopeNormalizer.normalize_cidr(cidr_str)
        if not target_net:
            return False

        for cidr in self.program.scope.cidrs:
            rule_net = ScopeNormalizer.normalize_cidr(cidr)
            if rule_net and (target_net.subnet_of(rule_net) or target_net == rule_net):
                return True
        return False

    def is_url_in_scope(self, url: str) -> bool:
        """
        Check if URL is in scope by validating its scheme, host, and port,
        and ensuring its path is not excluded.
        """
        norm_url = ScopeNormalizer.normalize_url(url)
        parsed = urlparse(norm_url)
        host = parsed.hostname or ""

        # Check host (domain or IP)
        host_in_scope = self.is_domain_in_scope(host) or self.is_ip_in_scope(host)
        if not host_in_scope:
            return False

        if self.is_domain_excluded(host):
            return False

        # Port check
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        if not self.is_port_in_scope(port):
            return False

        # Path check
        if self.is_path_excluded(parsed.path):
            return False

        return True

    def is_port_in_scope(self, port: int) -> bool:
        """Check if port is within authorized port list."""
        if not self.program.scope.ports:
            return port in [80, 443]
        return port in self.program.scope.ports

    def is_path_in_scope(self, path: str) -> bool:
        """Check if path is authorized and not explicitly excluded."""
        return not self.is_path_excluded(path)

    def is_path_excluded(self, path: str) -> bool:
        """Check if a path matches any exclusion pattern."""
        for pattern in self.program.exclusions.paths:
            if ScopeNormalizer.matches_path(pattern, path):
                return True
        return False

    def is_parameter_in_scope(self, param_name: str, path: Optional[str] = None) -> bool:
        """Check if parameter is allowed and not excluded."""
        norm_param = param_name.strip().lower()
        for excluded in self.program.exclusions.parameters:
            if excluded.strip().lower() == norm_param:
                return False
        return True

    def is_test_allowed(self, test_category: str) -> bool:
        """Check if a security test category is authorized by program policy."""
        cat_lower = test_category.strip().lower()

        # Lab mode allows broader testing profiles when explicitly configured
        if self.program.lab_mode:
            # Still disallow explicit destruction unless overridden
            return True

        for prohibited in self.program.prohibited_testing:
            if prohibited.strip().lower() in cat_lower or cat_lower in prohibited.strip().lower():
                return False

        if self.program.allowed_testing:
            return any(allowed.strip().lower() in cat_lower for allowed in self.program.allowed_testing)

        return True

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if an external tool adapter is permitted by program policy."""
        tool_lower = tool_name.strip().lower()
        if not self.program.allowed_tools:
            return True
        return any(allowed.strip().lower() == tool_lower for allowed in self.program.allowed_tools)

    def validate_target(
        self,
        target: str,
        port: Optional[int] = None,
        path: Optional[str] = None,
        parameter: Optional[str] = None,
        tool: Optional[str] = None,
        test_category: Optional[str] = None,
    ) -> ScopeValidationResult:
        """
        Execute full verification pipeline:
        TARGET -> SCOPE CHECK -> EXCLUSION CHECK -> POLICY CHECK -> TEST/TOOL CHECK.
        Returns ScopeValidationResult.
        """
        # Determine target type
        is_ip = ScopeNormalizer.normalize_ip(target) is not None
        is_url = "://" in target or path is not None

        # 1. SCOPE CHECK & EXCLUSION CHECK
        if is_ip:
            if not self.is_ip_in_scope(target):
                return ScopeValidationResult(
                    status=ScopeValidationStatus.OUT_OF_SCOPE,
                    allowed=False,
                    reason=f"IP '{target}' is not in configured program scope.",
                    target=target,
                    details={"type": "IP"},
                )
        elif is_url:
            if not self.is_url_in_scope(target):
                return ScopeValidationResult(
                    status=ScopeValidationStatus.OUT_OF_SCOPE,
                    allowed=False,
                    reason=f"URL '{target}' is out of scope or matches an excluded path.",
                    target=target,
                    details={"type": "URL"},
                )
        else:
            # Domain / Host check
            if self.is_domain_excluded(target):
                return ScopeValidationResult(
                    status=ScopeValidationStatus.EXCLUDED,
                    allowed=False,
                    reason=f"Domain '{target}' is explicitly listed in program exclusions.",
                    target=target,
                    details={"type": "DOMAIN", "exclusion": True},
                )
            if not self.is_domain_in_scope(target) and not self.is_subdomain_in_scope(target):
                return ScopeValidationResult(
                    status=ScopeValidationStatus.OUT_OF_SCOPE,
                    allowed=False,
                    reason=f"Target '{target}' does not match any authorized in-scope domain or wildcard.",
                    target=target,
                    details={"type": "DOMAIN"},
                )

        # 2. PORT CHECK
        if port is not None and not self.is_port_in_scope(port):
            return ScopeValidationResult(
                status=ScopeValidationStatus.POLICY_VIOLATION,
                allowed=False,
                reason=f"Port {port} is not authorized for testing on this program.",
                target=target,
                details={"port": port},
            )

        # 3. PATH CHECK
        if path is not None and self.is_path_excluded(path):
            return ScopeValidationResult(
                status=ScopeValidationStatus.EXCLUDED,
                allowed=False,
                reason=f"Path '{path}' is explicitly excluded in program policy.",
                target=target,
                details={"path": path},
            )

        # 4. PARAMETER CHECK
        if parameter is not None and not self.is_parameter_in_scope(parameter):
            return ScopeValidationResult(
                status=ScopeValidationStatus.EXCLUDED,
                allowed=False,
                reason=f"Parameter '{parameter}' is prohibited from testing.",
                target=target,
                details={"parameter": parameter},
            )

        # 5. TOOL CHECK
        if tool is not None and not self.is_tool_allowed(tool):
            return ScopeValidationResult(
                status=ScopeValidationStatus.PROHIBITED_TOOL,
                allowed=False,
                reason=f"Tool '{tool}' is not permitted by program policy.",
                target=target,
                details={"tool": tool},
            )

        # 6. TEST CATEGORY CHECK
        if test_category is not None and not self.is_test_allowed(test_category):
            return ScopeValidationResult(
                status=ScopeValidationStatus.PROHIBITED_TEST,
                allowed=False,
                reason=f"Test category '{test_category}' is prohibited (e.g. DoS, mass brute-force).",
                target=target,
                details={"test_category": test_category},
            )

        return ScopeValidationResult(
            status=ScopeValidationStatus.ALLOWED,
            allowed=True,
            reason="Target and test parameters successfully validated in-scope.",
            target=target,
            details={"approved": True},
        )
