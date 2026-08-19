from exposure360_api.logging import redact


def test_redact_removes_direct_and_nested_sensitive_values() -> None:
    payload = {
        "authorization": "Bearer should-not-appear",
        "database_url": "postgresql://user:password@host/db",
        "safe": {"nested_password": "should-not-appear", "count": 1},
        "items": [{"api_key": "should-not-appear"}, {"name": "safe"}],
    }

    redacted = redact(payload)

    assert redacted == {
        "authorization": "[REDACTED]",
        "database_url": "[REDACTED]",
        "safe": {"nested_password": "[REDACTED]", "count": 1},
        "items": [{"api_key": "[REDACTED]"}, {"name": "safe"}],
    }
