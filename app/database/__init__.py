"""
Database module for BugBounty-AI platform.
"""

from app.database.models import (
    Base,
    Program,
    ScopeRule,
    Asset,
    Domain,
    Subdomain,
    IPAddress,
    PortService,
    Technology,
    Endpoint,
    Parameter,
    APISpec,
    TestRun,
    Finding,
    EvidenceItem,
    AuditLog,
)
from app.database.session import engine, SessionLocal, init_db, get_db_session

__all__ = [
    "Base",
    "Program",
    "ScopeRule",
    "Asset",
    "Domain",
    "Subdomain",
    "IPAddress",
    "PortService",
    "Technology",
    "Endpoint",
    "Parameter",
    "APISpec",
    "TestRun",
    "Finding",
    "EvidenceItem",
    "AuditLog",
    "engine",
    "SessionLocal",
    "init_db",
    "get_db_session",
]
