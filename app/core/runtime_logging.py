from __future__ import annotations

import asyncio
import copy
import json
import logging
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import Request
from uvicorn.config import LOGGING_CONFIG
from uvicorn.logging import AccessFormatter, DefaultFormatter

from app.core.types import JsonValue
from app.core.utils.request_id import get_request_id

_SENSITIVE_LOG_VALUE_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)(\s*[=:]\s*)([^\s,&]+)"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(authorization\s*[=:]\s*)(?!\s*bearer\b)([^,&]+)"),
)
_JSON_SENSITIVE_LOG_VALUE_PATTERN = re.compile(
    r'(?i)("(?:password|passwd|pwd|token|secret|api[_-]?key|authorization)"\s*:\s*")'
    r'(?:\\.|[^"\\])*(")'
)
# ``scheme://user:pass@`` userinfo, e.g. aiohttp ConnectionKey proxy URL reprs.
_USERINFO_PATTERN = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s@'\"]+)@")
# Case-folded substrings that must be present before the keyed/bearer/
# authorization/JSON patterns above can match; keeps the per-record cost of
# credential-free lines to a casefold plus substring scans.
_SECRET_HINTS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "api-key",
    "apikey",
    "bearer",
    "authorization",
)
_LOG_REDACTION = "[REDACTED]"


def _redact_log_value(value: str | None) -> str | None:
    collapsed = _collapse_log_value(value)
    if collapsed is None:
        return None
    return _redact_secret_patterns(_USERINFO_PATTERN.sub(_redact_userinfo, collapsed))


def _redact_secret_patterns(text: str) -> str:
    redacted = _JSON_SENSITIVE_LOG_VALUE_PATTERN.sub(_redact_json_secret, text)
    redacted = _SENSITIVE_LOG_VALUE_PATTERNS[0].sub(_redact_keyed_secret, redacted)
    redacted = _SENSITIVE_LOG_VALUE_PATTERNS[1].sub(_redact_bearer_token, redacted)
    return _SENSITIVE_LOG_VALUE_PATTERNS[2].sub(_redact_authorization_value, redacted)


def redact_rendered_log_text(text: str, *, keyed_secrets: bool = True) -> str:
    """Mask URL userinfo (and, optionally, keyed secrets) in a rendered log string.

    Applied to every rendered record regardless of the originating logger
    (asyncio, aiohttp, uvicorn, tracebacks). ``keyed_secrets=False`` limits the
    pass to the O(1)-precheck userinfo pattern; formatters use it for INFO and
    lower records because the keyed patterns cost tens of microseconds on long
    hot-path lines. Never raises: any failure returns the input unchanged so
    logging itself cannot break.
    """
    try:
        redacted = text
        if "@" in text and "://" in text:
            redacted = _USERINFO_PATTERN.sub(_redact_userinfo, redacted)
        if not keyed_secrets:
            return redacted
        folded = text.casefold()
        for hint in _SECRET_HINTS:
            if hint in folded:
                return _redact_secret_patterns(redacted)
        return redacted
    except Exception:
        return text


def _redact_record_text(record: logging.LogRecord, text: str) -> str:
    return redact_rendered_log_text(text, keyed_secrets=record.levelno >= logging.WARNING)


def _redact_userinfo(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_LOG_REDACTION}@"


def _redact_keyed_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{_LOG_REDACTION}"


def _redact_json_secret(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_LOG_REDACTION}{match.group(2)}"


def _redact_bearer_token(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_LOG_REDACTION}"


def _redact_authorization_value(match: re.Match[str]) -> str:
    return f"{match.group(1)}{_LOG_REDACTION}"


def _utc_converter(seconds: float | None) -> time.struct_time:
    return time.gmtime(seconds)


class _RedactingFormatterMixin(logging.Formatter):
    """Redact the fully rendered record (message, exception text, stack info)."""

    def format(self, record: logging.LogRecord) -> str:
        return _redact_record_text(record, super().format(record))


class UtcDefaultFormatter(_RedactingFormatterMixin, DefaultFormatter):
    converter: Callable[[float | None], time.struct_time] = staticmethod(_utc_converter)


class UtcAccessFormatter(_RedactingFormatterMixin, AccessFormatter):
    converter: Callable[[float | None], time.struct_time] = staticmethod(_utc_converter)


def _redact_json_log_value(record: logging.LogRecord, value: object) -> object:
    if isinstance(value, str):
        return _redact_record_text(record, value)
    if isinstance(value, dict):
        return {key: _redact_json_log_value(record, item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_json_log_value(record, item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_record_text(record, record.getMessage()),
        }

        try:
            from app.core.tracing.otel import get_current_span_id, get_current_trace_id

            trace_id = get_current_trace_id()
            span_id = get_current_span_id()
            if trace_id:
                log_entry["trace_id"] = trace_id
            if span_id:
                log_entry["span_id"] = span_id
        except Exception:
            pass

        excluded_keys = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
            "taskName",
        }

        for key, value in record.__dict__.items():
            if key not in excluded_keys:
                try:
                    json.dumps(value)
                    log_entry[key] = _redact_json_log_value(record, value)
                except (TypeError, ValueError):
                    log_entry[key] = _redact_record_text(record, str(value))

        if record.exc_info:
            log_entry["exception"] = _redact_record_text(record, self.formatException(record.exc_info))

        return json.dumps(log_entry, default=str)


class JsonAccessFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, JsonValue] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "type": "access",
            "client": getattr(record, "client_addr", None),
            "request": cast(JsonValue, _redact_json_log_value(record, getattr(record, "request_line", None))),
            "status": getattr(record, "status_code", None),
        }
        return json.dumps(log_entry, default=str)


type LogConfigValue = str | bool | None | dict[str, "LogConfigValue"]
type LogConfig = dict[str, LogConfigValue]


def build_log_config() -> LogConfig:
    from app.core.config.settings import get_settings

    config = copy.deepcopy(LOGGING_CONFIG)
    formatters = config.setdefault("formatters", {})
    handlers = config.setdefault("handlers", {})
    settings = get_settings()

    if settings.log_format == "json":
        formatters["default"] = {
            "()": "app.core.runtime_logging.JsonFormatter",
        }
    else:
        formatters["default"] = {
            "()": "app.core.runtime_logging.UtcDefaultFormatter",
            "fmt": "%(asctime)s %(levelprefix)s %(name)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%SZ",
            "use_colors": None,
        }

    if settings.log_format == "json":
        formatters["access"] = {
            "()": "app.core.runtime_logging.JsonAccessFormatter",
        }
    else:
        formatters["access"] = {
            "()": "app.core.runtime_logging.UtcAccessFormatter",
            "fmt": '%(asctime)s %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            "datefmt": "%Y-%m-%dT%H:%M:%SZ",
            "use_colors": None,
        }

    # Uvicorn's stock config only wires uvicorn.* loggers. Attach the same
    # default handler to the root logger so application loggers such as
    # app.core.balancer.logic surface in docker logs at INFO.
    handlers.setdefault(
        "default", {"class": "logging.StreamHandler", "formatter": "default", "stream": "ext://sys.stderr"}
    )
    config["root"] = {
        "handlers": ["default"],
        "level": "INFO",
    }
    return cast(LogConfig, config)


class _RedactedRepr:
    """Stand-in whose repr is the redacted rendering of the original object."""

    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        self._text = text

    def __repr__(self) -> str:
        return self._text


# Context values the default handler renders as text rather than repr().
_UNREDACTED_LOOP_CONTEXT_KEYS = frozenset({"message", "exception", "source_traceback", "handle_traceback"})
_REDACTING_LOOP_HANDLER_MARKER = "_codex_lb_redacting_loop_handler"


def install_redacting_loop_exception_handler(loop: asyncio.AbstractEventLoop) -> None:
    """Redact credential-bearing object reprs before the loop's default handler logs them.

    The default asyncio/uvloop handler renders every context value with
    ``repr()`` (aiohttp ``Connection<ConnectionKey(... proxy=URL('http://u:pw@host'))>``,
    ``BasicAuth(... password='pw')``) into the ``asyncio`` logger before any
    formatter runs. Idempotent; delegates to the previously installed handler
    (or the default one) so formatting stays byte-identical for contexts that
    contain no secrets, and falls back to the raw context on any failure.
    """
    previous = loop.get_exception_handler()
    if previous is not None and getattr(previous, _REDACTING_LOOP_HANDLER_MARKER, False):
        return

    def _delegate(target_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        if previous is None:
            target_loop.default_exception_handler(context)
        else:
            previous(target_loop, context)

    def _handler(target_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        try:
            safe_context = dict(context)
            for key, value in context.items():
                if key in _UNREDACTED_LOOP_CONTEXT_KEYS:
                    continue
                try:
                    rendered = repr(value)
                except Exception:
                    continue
                redacted = redact_rendered_log_text(rendered)
                if redacted != rendered:
                    safe_context[key] = _RedactedRepr(redacted)
        except Exception:
            _delegate(target_loop, context)
            return
        _delegate(target_loop, safe_context)

    setattr(_handler, _REDACTING_LOOP_HANDLER_MARKER, True)
    loop.set_exception_handler(_handler)


def log_error_response(
    logger: logging.Logger,
    request: Request,
    status_code: int,
    code: str | None,
    message: str | None,
    *,
    category: str,
    exc_info: bool = False,
) -> None:
    level = logging.ERROR if status_code >= 500 else logging.WARNING
    logger.log(
        level,
        "%s request_id=%s method=%s path=%s status=%s code=%s message=%s",
        category,
        get_request_id(),
        request.method,
        request.url.path,
        status_code,
        _error_log_field(code),
        _error_log_field(message),
        exc_info=exc_info,
    )


def _error_log_field(value: str | None) -> str:
    redacted = _redact_log_value(value)
    if redacted is None:
        return "-"
    return json.dumps(redacted)


def _collapse_log_value(value: str | None) -> str | None:
    if value is None:
        return None
    collapsed = " ".join(value.split())
    return collapsed or None
