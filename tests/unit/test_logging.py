import logging

from solomon.logging import RedactingFormatter


def test_redaction_patterns():
    # Test that passwords are redacted
    assert RedactingFormatter.redact("password: mysecretpassword") == "password: [REDACTED]"
    assert RedactingFormatter.redact("Password=MySecret") == "Password=[REDACTED]"

    # Test API keys
    assert RedactingFormatter.redact("api_key = TESTKEY") == "api_key = [REDACTED]"

    # Test Authorization tokens
    assert (
        RedactingFormatter.redact("Authorization: Bearer my-jwt-token")
        == "Authorization: Bearer [REDACTED]"
    )

    # Test Cookies
    assert RedactingFormatter.redact("Cookie: session_id=123xyz") == "Cookie: [REDACTED]"

    # Test Private Keys
    private_key_log = (
        "Error loading key: -----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCqGKuk\n-----END RSA "
        "PRIVATE KEY-----"
    )
    redacted_key = RedactingFormatter.redact(private_key_log)
    assert "-----BEGIN" not in redacted_key
    assert "[REDACTED PRIVATE KEY]" in redacted_key

    # Normal text should remain untouched
    assert (
        RedactingFormatter.redact("Network connection established to 127.0.0.1")
        == "Network connection established to 127.0.0.1"
    )


def test_logging_formatter(caplog):
    logger = logging.getLogger("test_redaction")
    logger.setLevel(logging.INFO)

    # Clear existing handlers
    logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger.addHandler(handler)

    with caplog.at_level(logging.INFO, logger="test_redaction"):
        # Caplog captures the raw records by default, we need to format them ourselves
        # or we can test the formatter directly on the record
        record = logging.LogRecord(
            name="test_redaction",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User login failed for password: supersecret",
            args=(),
            exc_info=None,
        )
        formatted = handler.format(record)
        assert "supersecret" not in formatted
        assert "[REDACTED]" in formatted
