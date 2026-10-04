"""
SQLAlchemy 2.0 Database Models for BugBounty-AI.
Maps all core entities: programs, scope rules, assets, attack surface elements,
tests, findings, evidence, reports, and immutable audit logs.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Enum as SQLEnum,
)
from sqlalchemy.orm import declarative_base, relationship

from app.core.enums import (
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

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Program(Base):
    """Bug bounty or security assessment program definition."""
    __tablename__ = "programs"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    platform = Column(String(128), default="Private")
    description = Column(Text, default="")
    policy_url = Column(String(512), nullable=True)
    start_date = Column(String(64), nullable=True)
    end_date = Column(String(64), nullable=True)
    mode = Column(SQLEnum(OperatingMode), default=OperatingMode.PASSIVE)
    lab_mode = Column(Boolean, default=False)

    # Safety and limits
    rate_limit_rps = Column(Float, default=2.0)
    rate_limit_rpm = Column(Float, default=60.0)
    max_concurrency = Column(Integer, default=2)
    timeout_seconds = Column(Integer, default=15)

    # Policies & rules (stored as JSON arrays)
    prohibited_testing = Column(Text, default="[]")
    allowed_tools = Column(Text, default="[]")
    custom_rules = Column(Text, default="[]")
    authentication_notes = Column(Text, nullable=True)
    severity_policy = Column(Text, nullable=True)
    safe_harbor_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    scope_rules = relationship("ScopeRule", back_populates="program", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="program", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="program", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="program", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="program", cascade="all, delete-orphan")


class ScopeRule(Base):
    """Explicitly defined scope and exclusion boundaries."""
    __tablename__ = "scope_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_type = Column(SQLEnum(ScopeRuleType), nullable=False)
    effect = Column(SQLEnum(ScopeEffect), default=ScopeEffect.INCLUDE, nullable=False)
    pattern = Column(String(512), nullable=False, index=True)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utcnow)

    program = relationship("Program", back_populates="scope_rules")


class Asset(Base):
    """High-level attack surface asset (domain, IP, URL, or host)."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String(64), nullable=False)  # DOMAIN, IP, URL, SERVICE
    identifier = Column(String(512), nullable=False, index=True)
    in_scope = Column(Boolean, default=True)
    is_live = Column(Boolean, default=True)
    criticality = Column(String(32), default="MEDIUM")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    program = relationship("Program", back_populates="assets")


class Domain(Base):
    """Domain intelligence asset."""
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    domain_name = Column(String(255), nullable=False, index=True)
    is_wildcard = Column(Boolean, default=False)
    dns_records = Column(Text, default="{}")  # JSON representation of A, AAAA, MX, TXT, etc.
    created_at = Column(DateTime, default=utcnow)


class Subdomain(Base):
    """Discovered subdomains."""
    __tablename__ = "subdomains"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    subdomain = Column(String(255), nullable=False, index=True)
    cname = Column(String(255), nullable=True)
    is_live = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)


class IPAddress(Base):
    """Discovered IP addresses and network intel."""
    __tablename__ = "ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    ip_address = Column(String(64), nullable=False, index=True)
    asn = Column(String(64), nullable=True)
    org = Column(String(255), nullable=True)
    cloud_provider = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow)


class PortService(Base):
    """Discovered ports and service banners."""
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_id = Column(Integer, ForeignKey("ips.id", ondelete="CASCADE"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(16), default="tcp")
    state = Column(String(32), default="open")
    service_name = Column(String(64), nullable=True)
    banner = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Technology(Base):
    """Identified web or backend technologies and versions."""
    __tablename__ = "technologies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    category = Column(String(64), nullable=False)  # WAF, CMS, Framework, Web Server, Language
    name = Column(String(128), nullable=False)
    version = Column(String(64), nullable=True)
    confidence = Column(SQLEnum(ConfidenceLevel), default=ConfidenceLevel.MEDIUM)
    created_at = Column(DateTime, default=utcnow)


class Endpoint(Base):
    """Discovered HTTP endpoint."""
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(1024), nullable=False, index=True)
    path = Column(String(512), nullable=False)
    method = Column(String(16), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type = Column(String(128), nullable=True)
    content_length = Column(Integer, nullable=True)
    title = Column(String(255), nullable=True)
    auth_state = Column(String(64), default="unauthenticated")
    discovery_source = Column(String(64), default="passive")
    created_at = Column(DateTime, default=utcnow)

    program = relationship("Program", back_populates="endpoints")
    parameters = relationship("Parameter", back_populates="endpoint", cascade="all, delete-orphan")


class Parameter(Base):
    """Discovered query, body, path, or header parameter."""
    __tablename__ = "parameters"

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(128), nullable=False)
    param_type = Column(String(32), default="query")  # query, path, body, header, cookie, json
    is_sensitive = Column(Boolean, default=False)
    example_value = Column(String(255), nullable=True)

    endpoint = relationship("Endpoint", back_populates="parameters")


class APISpec(Base):
    """Discovered API definition and endpoints."""
    __tablename__ = "apis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    endpoint = Column(String(512), nullable=False)
    method = Column(String(16), default="GET")
    auth_type = Column(String(64), default="bearer")
    request_schema = Column(Text, nullable=True)
    response_schema = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class TestRun(Base):
    """Execution record for a test or reconnaissance task."""
    __tablename__ = "test_runs"

    id = Column(String(64), primary_key=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False)
    test_name = Column(String(128), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(String(32), default="SUCCESS")
    dry_run = Column(Boolean, default=False)
    command_executed = Column(Text, nullable=True)
    output_summary = Column(Text, nullable=True)
    start_time = Column(DateTime, default=utcnow)
    end_time = Column(DateTime, nullable=True)


class Finding(Base):
    """Validated or suspected vulnerability finding."""
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.DISCOVERED, nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.INFO, nullable=False)
    confidence = Column(SQLEnum(ConfidenceLevel), default=ConfidenceLevel.LOW, nullable=False)
    owasp_category = Column(SQLEnum(OWASPCategory), nullable=True)
    cwe_id = Column(String(32), nullable=True)
    endpoint = Column(String(1024), nullable=True)
    affected_asset = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    business_impact = Column(Text, nullable=True)
    technical_impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    human_reviewed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    program = relationship("Program", back_populates="findings")
    evidence_items = relationship("EvidenceItem", back_populates="finding", cascade="all, delete-orphan")


class EvidenceItem(Base):
    """Evidence artifact attached to a finding or test run."""
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True)
    finding_id = Column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    test_run_id = Column(String(64), nullable=True)
    evidence_type = Column(String(64), default="HTTP_DIFF")
    data = Column(Text, nullable=False)  # Redacted JSON or raw payload diff
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    finding = relationship("Finding", back_populates="evidence_items")


class AuditLog(Base):
    """
    Immutable audit log recording every scope check, command execution,
    recon event, and finding modification.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=utcnow, index=True, nullable=False)
    program_id = Column(String(64), ForeignKey("programs.id", ondelete="CASCADE"), nullable=True, index=True)
    target = Column(String(512), nullable=False)
    action = Column(SQLEnum(AuditAction), nullable=False)
    scope_result = Column(SQLEnum(ScopeValidationStatus), nullable=False)
    approval = Column(String(32), default="AUTO")
    tool = Column(String(64), nullable=True)
    result = Column(String(32), default="SUCCESS")
    details = Column(Text, default="{}")

    program = relationship("Program", back_populates="audit_logs")
