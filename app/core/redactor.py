"""
Security Redaction Layer.
Automatically detects and masks sensitive values:
- Passwords and secrets
- Authorization headers & Bearer tokens
- API keys, JWTs, and session tokens
- Private keys and certificate secrets
- Sensitive personal data
"""

import re
from typing import Any, Dict, List, Union


class SecurityRedactor:
    """Masks sensitive data in strings, HTTP headers, payloads, and JSON objects."""

    # Sensitive key patterns in dicts or headers
    SENSITIVE_KEY_PATTERNS = [
        re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key|auth|bearer|jwt|session|cookie|credential|private[_-]?key)", re.IGNORECASE)
    ]

    # Sensitive value regex patterns
    URL_CRED_PATTERN = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^:]+:)([^@/]+)(@)")
    BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
    BASIC_AUTH_PATTERN = re.compile(r"(Basic\s+)[A-Za-z0-9\+\/]+=*", re.IGNORECASE)
    JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")
    API_KEY_PATTERN = re.compile(r"(?:key|api|token|secret|password)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", re.IGNORECASE)
    PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----")

    REDACTED_STR = "[REDACTED_BY_BUGBOUNTY_AI]"

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Redact sensitive patterns from raw text/logs."""
        if not text:
            return text

        redacted = cls.URL_CRED_PATTERN.sub(r"\1" + cls.REDACTED_STR + r"\3", text)
        redacted = cls.PRIVATE_KEY_PATTERN.sub("-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----", redacted)
        redacted = cls.BEARER_PATTERN.sub(r"\1" + cls.REDACTED_STR, redacted)
        redacted = cls.BASIC_AUTH_PATTERN.sub(r"\1" + cls.REDACTED_STR, redacted)
        redacted = cls.JWT_PATTERN.sub("[REDACTED_JWT_TOKEN]", redacted)

        def _mask_api_key(match: re.Match) -> str:
            full = match.group(0)
            secret = match.group(1)
            return full.replace(secret, cls.REDACTED_STR)

        redacted = cls.API_KEY_PATTERN.sub(_mask_api_key, redacted)
        return redacted

    @classmethod
    def redact_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively redact dictionary values containing sensitive keys or patterns."""
        if not isinstance(data, dict):
            return data

        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            is_sensitive_key = any(pattern.search(str(key)) for pattern in cls.SENSITIVE_KEY_PATTERNS)

            if is_sensitive_key:
                sanitized[key] = cls.REDACTED_STR
            elif isinstance(value, dict):
                sanitized[key] = cls.redact_dict(value)
            elif isinstance(value, list):
                sanitized[key] = cls.redact_list(value)
            elif isinstance(value, str):
                sanitized[key] = cls.redact_text(value)
            else:
                sanitized[key] = value

        return sanitized

    @classmethod
    def redact_list(cls, items: List[Any]) -> List[Any]:
        """Recursively redact list items."""
        sanitized = []
        for item in items:
            if isinstance(item, dict):
                sanitized.append(cls.redact_dict(item))
            elif isinstance(item, list):
                sanitized.append(cls.redact_list(item))
            elif isinstance(item, str):
                sanitized.append(cls.redact_text(item))
            else:
                sanitized.append(item)
        return sanitized

    @classmethod
    def sanitize(cls, data: Union[str, Dict, List, Any]) -> Any:
        """Universal sanitizer handling strings, dictionaries, lists, and arbitrary structures."""
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            return cls.redact_dict(data)
        elif isinstance(data, list):
            return cls.redact_list(data)
        return data
