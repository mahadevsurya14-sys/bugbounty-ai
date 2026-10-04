"""
Scope Normalizer.
Handles normalization of:
- Hostnames, wildcard domains, schemes, ports
- IP addresses and CIDR subnets
- URLs, query parameters, and paths
- Trailing slashes and path traversal sequences
"""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse


class ScopeNormalizer:
    """Normalizes and canonicalizes network targets, hostnames, IPs, and URLs."""

    @staticmethod
    def normalize_domain(domain_or_host: str) -> str:
        """
        Normalize domain or hostname:
        - Strip whitespace and lowercase
        - Strip http:// or https:// if provided
        - Strip port if present
        - Strip trailing slashes or paths
        - Strip trailing dot
        """
        if not domain_or_host:
            return ""

        raw = domain_or_host.strip().lower()

        # If a scheme is included, parse hostname
        if "://" in raw:
            parsed = urlparse(raw)
            raw = parsed.hostname or raw

        # Strip path or query if someone typed domain.com/path
        if "/" in raw:
            raw = raw.split("/")[0]

        # Strip port if present (e.g. example.com:8080)
        if ":" in raw and not raw.startswith("["):  # not raw IPv6 without brackets
            # Check if it's host:port
            parts = raw.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                raw = parts[0]

        # Strip trailing dot
        raw = raw.rstrip(".")
        return raw

    @classmethod
    def matches_domain(cls, pattern: str, target: str) -> bool:
        """
        Test if target matches pattern.
        Supports exact matches and wildcards:
        - *.example.com matches api.example.com, test.sub.example.com
        - *.example.com does NOT match example-other.com or evil-example.com
        - example.com matches example.com
        """
        norm_pattern = cls.normalize_domain(pattern)
        norm_target = cls.normalize_domain(target)

        if not norm_pattern or not norm_target:
            return False

        if norm_pattern == norm_target:
            return True

        if norm_pattern.startswith("*."):
            base_domain = norm_pattern[2:]  # e.g. "example.com"
            # Target must end with ".base_domain"
            if norm_target.endswith("." + base_domain):
                return True
            # In some bug bounty programs, *.example.com also includes the apex example.com
            if norm_target == base_domain:
                return True

        return False

    @staticmethod
    def normalize_ip(ip_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Parse and normalize an IP address."""
        try:
            return ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return None

    @staticmethod
    def normalize_cidr(cidr_str: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse and normalize a CIDR network block."""
        try:
            return ipaddress.ip_network(cidr_str.strip(), strict=False)
        except ValueError:
            return None

    @classmethod
    def is_ip_in_cidr(cls, ip_str: str, cidr_str: str) -> bool:
        """Check if an IP address belongs to a CIDR block."""
        ip = cls.normalize_ip(ip_str)
        network = cls.normalize_cidr(cidr_str)
        if ip and network:
            return ip in network
        return False

    @classmethod
    def normalize_url(cls, url: str) -> str:
        """
        Canonicalize a URL:
        - Scheme lowercased
        - Host lowercased and stripped of default ports (80 for http, 443 for https)
        - Collapse double slashes in path
        - Remove default root trailing slash consistency
        """
        if not url:
            return ""

        raw = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
            raw = "https://" + raw

        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        # Handle port
        port = parsed.port
        netloc = hostname
        if port:
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = hostname
            else:
                netloc = f"{hostname}:{port}"

        # Normalize path
        path = parsed.path or "/"
        # Collapse multiple slashes
        path = re.sub(r"/{2,}", "/", path)

        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))

    @classmethod
    def matches_path(cls, pattern: str, path: str) -> bool:
        """
        Check if a given path matches an inclusion or exclusion path pattern.
        Supports prefix matching and regex patterns.
        """
        if not pattern or not path:
            return False

        norm_path = "/" + path.strip("/")
        norm_pattern = "/" + pattern.strip("/")

        if norm_pattern == norm_path:
            return True

        if norm_pattern.endswith("*"):
            prefix = norm_pattern[:-1]
            return norm_path.startswith(prefix)

        # Regex fallback
        try:
            if re.search(pattern, path):
                return True
        except re.error:
            pass

        return False
