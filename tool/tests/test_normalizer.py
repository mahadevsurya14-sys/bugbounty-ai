"""
Unit tests for ScopeNormalizer.
"""

from app.scope.normalizer import ScopeNormalizer


def test_domain_normalization():
    assert ScopeNormalizer.normalize_domain("EXAMPLE.COM") == "example.com"
    assert ScopeNormalizer.normalize_domain("https://api.example.com:8443/v1") == "api.example.com"
    assert ScopeNormalizer.normalize_domain("dev.example.com.") == "dev.example.com"
    assert ScopeNormalizer.normalize_domain("http://target.local:80") == "target.local"


def test_wildcard_domain_matching():
    pattern = "*.example.com"
    assert ScopeNormalizer.matches_domain(pattern, "api.example.com") is True
    assert ScopeNormalizer.matches_domain(pattern, "sub.dev.example.com") is True
    assert ScopeNormalizer.matches_domain(pattern, "example.com") is True

    # Must NOT match similar or malicious domains
    assert ScopeNormalizer.matches_domain(pattern, "evil-example.com") is False
    assert ScopeNormalizer.matches_domain(pattern, "notexample.com") is False
    assert ScopeNormalizer.matches_domain(pattern, "example.org") is False


def test_ip_and_cidr_matching():
    cidr = "10.0.0.0/24"
    assert ScopeNormalizer.is_ip_in_cidr("10.0.0.1", cidr) is True
    assert ScopeNormalizer.is_ip_in_cidr("10.0.0.254", cidr) is True
    assert ScopeNormalizer.is_ip_in_cidr("10.0.1.1", cidr) is False
    assert ScopeNormalizer.is_ip_in_cidr("192.168.1.1", cidr) is False


def test_url_normalization():
    raw_url = "HTTP://Example.COM:80/path//to/resource?query=1"
    norm = ScopeNormalizer.normalize_url(raw_url)
    assert norm == "http://example.com/path/to/resource?query=1"

    https_url = "HTTPS://API.EXAMPLE.COM:443/"
    assert ScopeNormalizer.normalize_url(https_url) == "https://api.example.com/"


def test_path_matching():
    pattern = "/api/v1/*"
    assert ScopeNormalizer.matches_path(pattern, "/api/v1/users") is True
    assert ScopeNormalizer.matches_path(pattern, "/api/v1/posts/10") is True
    assert ScopeNormalizer.matches_path(pattern, "/api/v2/users") is False
