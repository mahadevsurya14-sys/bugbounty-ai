"""
Scope Importer.
Imports program scope and boundaries from:
- JSON files
- YAML files
- CSV files
- Raw manual input
"""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from app.core.config import (
    ExclusionConfig,
    ProgramConfig,
    RateLimitConfig,
    ScopeDefinitionConfig,
)
from app.scope.normalizer import ScopeNormalizer


class ScopeImporter:
    """Imports and parses scope rules into structured ProgramConfig objects."""

    @classmethod
    def import_from_yaml(cls, file_path: str) -> ProgramConfig:
        """Parse program configuration from a YAML file."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        prog_data = data.get("program", data)
        return ProgramConfig(**prog_data)

    @classmethod
    def import_from_json(cls, file_path: str) -> ProgramConfig:
        """Parse program configuration from a JSON file."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        prog_data = data.get("program", data)
        return ProgramConfig(**prog_data)

    @classmethod
    def import_from_csv(
        cls,
        file_path: str,
        program_id: str,
        program_name: str,
        platform: str = "HackerOne",
    ) -> ProgramConfig:
        """
        Parse scope rules from a CSV file.
        Accepts columns: asset, type (domain, ip, cidr, url), eligible/status (in-scope / out-of-scope).
        """
        path = Path(file_path)
        in_scope_domains = []
        in_scope_subdomains = []
        in_scope_ips = []
        in_scope_cidrs = []
        in_scope_urls = []
        excluded_domains = []

        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Normalize keys to lowercase
                norm_row = {k.strip().lower(): v.strip() for k, v in row.items() if k}
                asset = norm_row.get("asset") or norm_row.get("target") or norm_row.get("identifier") or ""
                asset_type = norm_row.get("type", "domain").lower()
                status = norm_row.get("eligible", norm_row.get("status", norm_row.get("scope", "in-scope"))).lower()

                if not asset:
                    continue

                is_in_scope = "in" in status and "out" not in status

                if not is_in_scope:
                    excluded_domains.append(asset)
                    continue

                if asset_type == "domain":
                    if asset.startswith("*."):
                        in_scope_domains.append(asset)
                    else:
                        in_scope_domains.append(asset)
                elif asset_type in ("ip", "ipv4", "ipv6"):
                    in_scope_ips.append(asset)
                elif asset_type == "cidr":
                    in_scope_cidrs.append(asset)
                elif asset_type in ("url", "endpoint"):
                    in_scope_urls.append(asset)
                else:
                    # Auto-detect
                    if ScopeNormalizer.normalize_ip(asset):
                        in_scope_ips.append(asset)
                    elif "/" in asset and ScopeNormalizer.normalize_cidr(asset):
                        in_scope_cidrs.append(asset)
                    elif "://" in asset:
                        in_scope_urls.append(asset)
                    else:
                        in_scope_domains.append(asset)

        return ProgramConfig(
            program_id=program_id,
            program_name=program_name,
            platform=platform,
            scope=ScopeDefinitionConfig(
                domains=in_scope_domains,
                subdomains=in_scope_subdomains,
                ips=in_scope_ips,
                cidrs=in_scope_cidrs,
                urls=in_scope_urls,
            ),
            exclusions=ExclusionConfig(
                domains=excluded_domains,
            ),
        )

    @classmethod
    def format_scope_summary(cls, program: ProgramConfig) -> str:
        """Create a human-readable scope summary as required by specifications."""
        in_domains = ", ".join(program.scope.domains) if program.scope.domains else "(None)"
        in_ips = ", ".join(program.scope.ips) if program.scope.ips else ""
        in_cidrs = ", ".join(program.scope.cidrs) if program.scope.cidrs else ""
        scope_str = in_domains
        if in_ips:
            scope_str += f" | IPs: {in_ips}"
        if in_cidrs:
            scope_str += f" | CIDRs: {in_cidrs}"

        ex_domains = ", ".join(program.exclusions.domains) if program.exclusions.domains else "(None)"
        ex_paths = ", ".join(program.exclusions.paths) if program.exclusions.paths else ""
        ex_str = ex_domains
        if ex_paths:
            ex_str += f" | Excluded Paths: {ex_paths}"

        return f"""## PROGRAM

Name: {program.program_name}
Platform: {program.platform}
Scope: {scope_str}
Excluded: {ex_str}
Rate Limit: {program.limits.requests_per_second} req/sec (max concurrency: {program.limits.max_concurrency})
Authentication: {program.authentication_notes or 'Standard unauthenticated / researcher test credentials'}
Special Rules: {', '.join(program.custom_rules) if program.custom_rules else 'Standard Safe Harbor & Scope Enforcement'}
Status: ACTIVE
"""
