import logging
import re


class RedactingFormatter(logging.Formatter):
    """
    A logging formatter that redacts sensitive information.
    """

    # Patterns that resemble sensitive information
    REDACTION_PATTERNS = [
        re.compile(r"(?i)(password\s*[:=]\s*)[^\s,\]\}]+"),
        re.compile(r"(?i)(token\s*[:=]\s*)[^\s,\]\}]+"),
        re.compile(r"(?i)(api_key\s*[:=]\s*)[^\s,\]\}]+"),
        re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,\]\}]+"),
        re.compile(r"(?i)(cookie\s*[:=]\s*)[^\s,\]\}]+"),
        re.compile(r"(?i)(secret\s*[:=]\s*)[^\s,\]\}]+"),
        # Private key basic matching
        re.compile(r"-----BEGIN.*?PRIVATE KEY-----.*?-----END.*?PRIVATE KEY-----", re.DOTALL),
    ]

    REDACTED_STR = r"\1[REDACTED]"

    def format(self, record: logging.LogRecord) -> str:
        original_msg = super().format(record)
        return self.redact(original_msg)

    @classmethod
    def redact(cls, text: str) -> str:
        if not isinstance(text, str):
            return text

        redacted_text = text
        for pattern in cls.REDACTION_PATTERNS:
            if "PRIVATE KEY" in pattern.pattern:
                redacted_text = pattern.sub("[REDACTED PRIVATE KEY]", redacted_text)
            else:
                redacted_text = pattern.sub(cls.REDACTED_STR, redacted_text)
        return redacted_text


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Sets up the global logging configuration with redaction."""
    logger = logging.getLogger("solomon")
    logger.setLevel(level)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        formatter = RedactingFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

    return logger
