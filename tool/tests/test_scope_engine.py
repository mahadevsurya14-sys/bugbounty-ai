"""
Unit tests for ScopeEngine.
Validates authorization, wildcards, CIDRs, exclusions, and prohibited actions.
"""

import pytest
from app.core.config import ExclusionConfig, ProgramConfig, RateLimitConfig, ScopeDefinitionConfig
from app.core.enums import ScopeValidationStatus
from app.scope.engine import ScopeEngine


@pytest.fixture
def sample_program() -> ProgramConfig:
    return ProgramConfig(
        program_id="test_bounty",
        program_name="Test Bounty Program",
        scope=ScopeDefinitionConfig(
            domains=["*.example.com", "partner.org"],
            ips=["192.168.1.50"],
            cidrs=["10.10.0.0/16"],
            urls=["https://special.example.com/api/"],
            ports=[80, 443, 8443],
        ),
        exclusions=ExclusionConfig(
            domains=["forbidden.example.com"],
            paths=["/admin/supersecret", "/logout"],
            parameters=["debug_token"],
        ),
        prohibited_testing=["denial_of_service", "credential_stuffing"],
        allowed_tools=["curl", "httpx", "nmap", "ping"],
    )


def test_domain_scope_and_exclusions(sample_program):
    engine = ScopeEngine(sample_program)

    # In scope wildcard
    assert engine.is_domain_in_scope("api.example.com") is True
    assert engine.is_domain_in_scope("dev.sub.example.com") is True

    # In scope exact domain
    assert engine.is_domain_in_scope("partner.org") is True

    # Out of scope domain
    assert engine.is_domain_in_scope("unauthorized.com") is False

    # Exclusion overrides
    assert engine.is_domain_excluded("forbidden.example.com") is True
    res = engine.validate_target("forbidden.example.com")
    assert res.allowed is False
    assert res.status == ScopeValidationStatus.EXCLUDED


def test_ip_and_cidr_scope(sample_program):
    engine = ScopeEngine(sample_program)

    # Exact IP
    assert engine.is_ip_in_scope("192.168.1.50") is True
    assert engine.is_ip_in_scope("192.168.1.51") is False

    # CIDR subnet
    assert engine.is_ip_in_scope("10.10.5.20") is True
    assert engine.is_ip_in_scope("10.11.0.1") is False


def test_path_and_parameter_exclusions(sample_program):
    engine = ScopeEngine(sample_program)

    # Allowed path
    res_path = engine.validate_target("api.example.com", path="/api/v1/users")
    assert res_path.allowed is True

    # Excluded path
    res_ex_path = engine.validate_target("api.example.com", path="/admin/supersecret")
    assert res_ex_path.allowed is False
    assert res_ex_path.status == ScopeValidationStatus.EXCLUDED

    # Excluded parameter
    res_param = engine.validate_target("api.example.com", parameter="debug_token")
    assert res_param.allowed is False
    assert res_param.status == ScopeValidationStatus.EXCLUDED


def test_prohibited_tests_and_tools(sample_program):
    engine = ScopeEngine(sample_program)

    # Allowed tool
    res_tool = engine.validate_target("api.example.com", tool="curl")
    assert res_tool.allowed is True

    # Prohibited tool
    res_bad_tool = engine.validate_target("api.example.com", tool="sqlmap_extreme")
    assert res_bad_tool.allowed is False
    assert res_bad_tool.status == ScopeValidationStatus.PROHIBITED_TOOL

    # Prohibited test category (DoS / Credential stuffing)
    res_dos = engine.validate_target("api.example.com", test_category="denial_of_service")
    assert res_dos.allowed is False
    assert res_dos.status == ScopeValidationStatus.PROHIBITED_TEST
