"""
Configuration management and validation for BugBounty-AI platform.
Supports loading programs and system settings from YAML, JSON, or environment variables.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field

from app.core.enums import OperatingMode


class RateLimitConfig(BaseModel):
    """Rate limit and concurrency settings."""
    requests_per_second: float = Field(default=2.0, ge=0.1, le=100.0)
    requests_per_minute: float = Field(default=60.0, ge=1.0, le=3000.0)
    max_concurrency: int = Field(default=2, ge=1, le=50)
    max_requests_per_target: int = Field(default=1000, ge=1)
    cooldown_seconds: float = Field(default=0.5, ge=0.0)
    timeout_seconds: int = Field(default=15, ge=1, le=300)


class ScopeDefinitionConfig(BaseModel):
    """Explicitly authorized in-scope boundaries."""
    domains: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    cidrs: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=lambda: [80, 443])


class ExclusionConfig(BaseModel):
    """Explicitly excluded boundaries, paths, and components."""
    domains: List[str] = Field(default_factory=list)
    paths: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)


class ProgramConfig(BaseModel):
    """Configuration specification for a security bug bounty program or lab."""
    program_id: str
    program_name: str
    platform: str = "HackerOne / Bugcrowd / Private"
    description: str = ""
    policy_url: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    mode: OperatingMode = OperatingMode.PASSIVE
    lab_mode: bool = False
    scope: ScopeDefinitionConfig = Field(default_factory=ScopeDefinitionConfig)
    exclusions: ExclusionConfig = Field(default_factory=ExclusionConfig)
    limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    allowed_testing: List[str] = Field(default_factory=list)
    prohibited_testing: List[str] = Field(
        default_factory=lambda: [
            "denial_of_service",
            "credential_stuffing",
            "mass_password_guessing",
            "destructive_exploitation",
            "persistence_deployment",
            "data_destruction"
        ]
    )
    allowed_tools: List[str] = Field(default_factory=lambda: ["httpx", "dnsx", "subfinder", "nmap", "ffuf", "katana", "curl"])
    authentication_notes: Optional[str] = None
    severity_policy: Optional[str] = None
    safe_harbor_notes: Optional[str] = None
    custom_rules: List[str] = Field(default_factory=list)


class PlatformSettings(BaseModel):
    """Global system configuration."""
    database_url: str = Field(default="sqlite:///data/bugbounty.db")
    default_mode: OperatingMode = Field(default=OperatingMode.PASSIVE)
    log_level: str = Field(default="INFO")
    log_file: str = Field(default="logs/audit.jsonl")
    redact_secrets: bool = Field(default=True)
    dry_run_default: bool = Field(default=False)


def load_platform_settings() -> PlatformSettings:
    """Load platform settings with environment overrides."""
    db_url = os.getenv("BUGBOUNTY_DATABASE_URL", "sqlite:///data/bugbounty.db")
    mode_str = os.getenv("BUGBOUNTY_DEFAULT_MODE", "PASSIVE")
    mode = OperatingMode(mode_str) if mode_str in OperatingMode.__members__ else OperatingMode.PASSIVE
    log_file = os.getenv("BUGBOUNTY_LOG_FILE", "logs/audit.jsonl")

    return PlatformSettings(
        database_url=db_url,
        default_mode=mode,
        log_file=log_file,
        redact_secrets=os.getenv("BUGBOUNTY_REDACT_SECRETS", "true").lower() == "true",
    )


def load_program_from_yaml(file_path: str) -> ProgramConfig:
    """Load and validate a Program configuration from a YAML file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML content in {file_path}")

    program_data = data.get("program", data)
    return ProgramConfig(**program_data)
