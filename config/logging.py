"""Small structured JSON logging foundation for WireScope."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import sys
from typing import Any


STANDARD_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}
LOG_CONTEXT: ContextVar[dict[str, Any]] = ContextVar(
    "wirescope_log_context",
    default={},
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "component": record.name,
            "message": record.getMessage(),
        }
        payload.update(LOG_CONTEXT.get())

        for key, value in record.__dict__.items():
            if key not in STANDARD_RECORD_FIELDS and not key.startswith("_"):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger("wirescope")
    root.setLevel(level.upper())
    root.propagate = False

    if root.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)


def get_logger(component: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(f"wirescope.{component}")


@contextmanager
def bind_log_context(**values: Any) -> Iterator[None]:
    context = {**LOG_CONTEXT.get(), **values}
    token = LOG_CONTEXT.set(context)
    try:
        yield
    finally:
        LOG_CONTEXT.reset(token)
