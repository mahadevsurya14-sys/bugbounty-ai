"""
Unit tests for SecurityRedactor.
Verifies redaction of tokens, JWTs, API keys, passwords, and auth headers.
"""

from app.core.redactor import SecurityRedactor


def test_bearer_token_redaction():
    raw_header = "Authorization: Bearer mySecretToken1234567890abcdef"
    redacted = SecurityRedactor.redact_text(raw_header)
    assert "mySecretToken1234567890abcdef" not in redacted
    assert "Authorization: Bearer [REDACTED_BY_BUGBOUNTY_AI]" in redacted


def test_jwt_redaction():
    raw = "Here is a token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this_signature"
    redacted = SecurityRedactor.redact_text(raw)
    assert "do_not_leak_this_signature" not in redacted
    assert "[REDACTED_JWT_TOKEN]" in redacted


def test_dict_recursive_redaction():
    data = {
        "username": "researcher1",
        "password": "UltraSecretPassword99!",
        "auth_token": "token_abc1234567890",
        "nested": {
            "api_key": "live_key_9876543210fedcba",
            "normal_field": "public_data",
        },
        "items": [
            {"session_id": "sess_abcdef12345"},
            "safe string",
        ],
    }

    sanitized = SecurityRedactor.redact_dict(data)
    assert sanitized["password"] == SecurityRedactor.REDACTED_STR
    assert sanitized["auth_token"] == SecurityRedactor.REDACTED_STR
    assert sanitized["nested"]["api_key"] == SecurityRedactor.REDACTED_STR
    assert sanitized["nested"]["normal_field"] == "public_data"
    assert sanitized["items"][0]["session_id"] == SecurityRedactor.REDACTED_STR
