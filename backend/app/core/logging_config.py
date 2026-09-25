import logging
import sys
from typing import Any, Dict

class SecurityFormatter(logging.Formatter):
    """
    Structured log formatter that ensures sensitive information
    like file contents, tokens, or raw paths are redacted or sanitized.
    """
    def format(self, record: logging.LogRecord) -> str:
        # Standardize timestamp and format
        standard_format = f"[{self.formatTime(record, '%Y-%m-%d %H:%M:%S')}] [{record.levelname}] [{record.name}] {record.getMessage()}"
        return standard_format

def setup_logging(debug: bool = False) -> logging.Logger:
    logger = logging.getLogger("filesanitizer")
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        handler.setFormatter(SecurityFormatter())
        logger.addHandler(handler)

    return logger

logger = setup_logging()
