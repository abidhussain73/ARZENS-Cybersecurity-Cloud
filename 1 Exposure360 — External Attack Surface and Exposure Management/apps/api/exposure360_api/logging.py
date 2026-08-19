import logging
from collections.abc import MutableMapping
from typing import Any

import structlog

SENSITIVE_MARKERS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "api_key",
    "database_url",
)


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _is_sensitive_key(key: object) -> bool:
    return isinstance(key, str) and any(marker in key.lower() for marker in SENSITIVE_MARKERS)


def redact_event(_: Any, __: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    return {key: redact(value) for key, value in event_dict.items()}


def configure_logging() -> None:
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            redact_event,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )
