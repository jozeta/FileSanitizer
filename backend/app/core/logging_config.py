import collections
import logging
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

MAX_AUDIT_LOG_RECORDS = 5000

class SecurityFormatter(logging.Formatter):
    """
    Structured log formatter that ensures sensitive information
    like tokens or authorization headers are redacted or sanitized.
    """
    REDACT_PATTERNS = [
        (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{20,}'), r'\1[REDACTED_JWT]'),
        (re.compile(r'(?i)(password\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED]\3'),
        (re.compile(r'(?i)(api[_-]?key\s*[:=]\s*["\'])([^"\']+)(["\'])'), r'\1[REDACTED_KEY]\3'),
    ]

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        for pat, repl in self.REDACT_PATTERNS:
            msg = pat.sub(repl, msg)
        standard_format = f"[{self.formatTime(record, '%Y-%m-%d %H:%M:%S')}] [{record.levelname}] [{record.name}] {msg}"
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            standard_format += f"\n{record.exc_text}"
        return standard_format


class AuditLogManager:
    """
    In-memory thread-safe circular ring buffer for real-time audit
    and debug logging, queryable by administrators via Settings.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._buffer = collections.deque(maxlen=MAX_AUDIT_LOG_RECORDS)
                cls._instance._counter = 0
                cls._instance._current_level = "INFO"
        return cls._instance

    def add_record(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            for pat, repl in SecurityFormatter.REDACT_PATTERNS:
                msg = pat.sub(repl, msg)

            exc_str = None
            if record.exc_info:
                import traceback
                exc_str = "".join(traceback.format_exception(*record.exc_info))
            elif record.exc_text:
                exc_str = record.exc_text

            now = datetime.now(timezone.utc)
            entry = {
                "id": self._counter,
                "timestamp": now.isoformat(),
                "time_str": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "epoch": record.created,
                "level": record.levelname,
                "logger": record.name,
                "module": record.module,
                "func": record.funcName,
                "line": record.lineno,
                "message": msg,
                "exception": exc_str,
            }
            with self._lock:
                self._counter += 1
                self._buffer.append(entry)
        except Exception:
            pass

    def get_logs(
        self,
        limit: int = 300,
        level: Optional[str] = None,
        search: Optional[str] = None,
        offset: int = 0
    ) -> Dict[str, Any]:
        with self._lock:
            records = list(self._buffer)

        # Count levels across full buffer
        counts = {"TOTAL": len(records), "DEBUG": 0, "INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
        for r in records:
            lvl = r.get("level", "INFO")
            if lvl in counts:
                counts[lvl] += 1

        # Reverse so newest are first
        records.reverse()

        # Filter by severity level
        if level and level.upper() not in ["ALL", ""]:
            target_lvl = level.upper()
            if target_lvl == "WARNING":
                records = [r for r in records if r.get("level") in ["WARNING", "ERROR", "CRITICAL"]]
            elif target_lvl == "ERROR":
                records = [r for r in records if r.get("level") in ["ERROR", "CRITICAL"]]
            else:
                records = [r for r in records if r.get("level") == target_lvl]

        # Filter by search string
        if search and search.strip():
            q = search.strip().lower()
            records = [
                r for r in records
                if q in r.get("message", "").lower()
                or q in r.get("module", "").lower()
                or q in r.get("logger", "").lower()
                or (r.get("exception") and q in r.get("exception", "").lower())
            ]

        total_filtered = len(records)
        sliced = records[offset : offset + limit]

        return {
            "total": total_filtered,
            "counts": counts,
            "current_level": self._current_level,
            "logs": sliced
        }

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

    def set_level(self, level_name: str) -> str:
        clean = level_name.strip().upper()
        lvl = getattr(logging, clean, logging.INFO)
        with self._lock:
            self._current_level = clean
        logging.getLogger("filesanitizer").setLevel(lvl)
        logging.getLogger().setLevel(lvl)
        return clean

    def export_text(self) -> str:
        with self._lock:
            records = list(self._buffer)
        lines = []
        for r in records:
            line = f"[{r.get('time_str')}] [{r.get('level')}] [{r.get('logger')}:{r.get('module')}:{r.get('line')}] {r.get('message')}"
            if r.get("exception"):
                line += f"\n{r.get('exception')}"
            lines.append(line)
        return "\n".join(lines)


audit_log_manager = AuditLogManager()


class AuditLogHandler(logging.Handler):
    """Custom logging Handler routing log records to the AuditLogManager buffer."""
    def emit(self, record: logging.LogRecord) -> None:
        audit_log_manager.add_record(record)


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

    # Attach audit handler if not present
    has_audit = any(isinstance(h, AuditLogHandler) for h in logger.handlers)
    if not has_audit:
        audit_handler = AuditLogHandler()
        audit_handler.setLevel(logging.DEBUG)
        logger.addHandler(audit_handler)

        # Also attach to root logger so framework/worker logs are captured
        root_logger = logging.getLogger()
        if not any(isinstance(h, AuditLogHandler) for h in root_logger.handlers):
            root_logger.addHandler(audit_handler)

    return logger

logger = setup_logging()
