from __future__ import annotations

import io
import json
import logging

import pytest

import app.core.runtime_logging as runtime_logging
from app.core.runtime_logging import (
    JsonAccessFormatter,
    JsonFormatter,
    UtcAccessFormatter,
    UtcDefaultFormatter,
    _error_log_field,
    _redact_log_value,
    build_log_config,
)
from tests.unit._proxy_test_helpers import runtime_basic_auth_url

pytestmark = pytest.mark.unit


def test_redact_log_value_masks_keyed_secrets_and_bearer_tokens():
    value = "password=secret-token Authorization: Bearer abc.def api_key=abc123"

    redacted = _redact_log_value(value)

    assert redacted == "password=[REDACTED] Authorization: Bearer [REDACTED] api_key=[REDACTED]"


def test_redact_log_value_masks_basic_authorization_credentials():
    value = "Authorization: Basic dXNlcjpwYXNz, status=failed"

    redacted = _redact_log_value(value)

    assert redacted == "Authorization: [REDACTED], status=failed"


def test_error_log_field_quotes_redacted_field_values():
    value = "temporary failure status=200 request_id=req-1 api_key=abc123"

    field = _error_log_field(value)

    assert field == '"temporary failure status=200 request_id=req-1 api_key=[REDACTED]"'


@pytest.mark.parametrize(
    "value, expected",
    [
        ('provider error {"api_key":"sk-secret"}', 'provider error {"api_key":"[REDACTED]"}'),
        ('provider error {"authorization":"Basic dXNlcjpwYXNz"}', 'provider error {"authorization":"[REDACTED]"}'),
    ],
)
def test_error_log_field_redacts_json_style_secrets(value, expected):
    assert _error_log_field(value) == json.dumps(expected)


@pytest.fixture
def json_formatter():
    return JsonFormatter()


@pytest.fixture
def text_formatter():
    return UtcDefaultFormatter(
        fmt="%(asctime)s %(levelprefix)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        use_colors=None,
    )


def test_json_formatter_produces_valid_json(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    output = json_formatter.format(record)
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_json_formatter_includes_required_fields(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.WARNING,
        pathname="test.py",
        lineno=42,
        msg="Test warning",
        args=(),
        exc_info=None,
    )
    output = json_formatter.format(record)
    parsed = json.loads(output)

    assert "timestamp" in parsed
    assert "level" in parsed
    assert "logger" in parsed
    assert "message" in parsed
    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "test.module"
    assert parsed["message"] == "Test warning"


def test_json_formatter_includes_extra_fields(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    record.request_id = "req-123"
    record.user_id = "user-456"

    output = json_formatter.format(record)
    parsed = json.loads(output)

    assert parsed["request_id"] == "req-123"
    assert parsed["user_id"] == "user-456"


def test_json_formatter_handles_non_serializable_objects(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    class CustomObject:
        def __repr__(self):
            return "<CustomObject>"

    record.custom_field = CustomObject()

    output = json_formatter.format(record)
    parsed = json.loads(output)

    assert "custom_field" in parsed
    assert parsed["custom_field"] == "<CustomObject>"


def test_json_formatter_includes_exception_info(json_formatter):
    try:
        raise ValueError("Test error")
    except ValueError:
        import sys

        exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test.module",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )

    output = json_formatter.format(record)
    parsed = json.loads(output)

    assert "exception" in parsed
    assert "ValueError: Test error" in parsed["exception"]


def test_json_formatter_with_formatted_message(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="User %s logged in from %s",
        args=("alice", "192.168.1.1"),
        exc_info=None,
    )
    output = json_formatter.format(record)
    parsed = json.loads(output)

    assert parsed["message"] == "User alice logged in from 192.168.1.1"


def test_text_formatter_not_json(text_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    output = text_formatter.format(record)

    with pytest.raises(json.JSONDecodeError):
        json.loads(output)

    assert "test.module" in output
    assert "Test message" in output


def test_json_formatter_timestamp_is_iso_format(json_formatter):
    record = logging.LogRecord(
        name="test.module",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    output = json_formatter.format(record)
    parsed = json.loads(output)

    timestamp = parsed["timestamp"]
    assert "T" in timestamp
    assert "+" in timestamp or "Z" in timestamp or timestamp.endswith("00:00")


def test_build_log_config_uses_json_access_formatter_when_json(monkeypatch):
    """build_log_config() should use JsonAccessFormatter when log_format == 'json'."""
    from typing import cast

    monkeypatch.setenv("CODEX_LB_LOG_FORMAT", "json")
    # Clear lru_cache so the setting is re-read
    from app.core.config.settings import get_settings

    get_settings.cache_clear()
    config = build_log_config()
    formatters = cast(dict, config.get("formatters", {}))
    access_formatter = cast(dict, formatters.get("access", {}))
    assert access_formatter.get("()") == "app.core.runtime_logging.JsonAccessFormatter"
    # Restore
    get_settings.cache_clear()


def test_build_log_config_uses_utc_access_formatter_when_text(monkeypatch):
    """build_log_config() should use UtcAccessFormatter when log_format == 'text'."""
    from typing import cast

    monkeypatch.setenv("CODEX_LB_LOG_FORMAT", "text")
    from app.core.config.settings import get_settings

    get_settings.cache_clear()
    config = build_log_config()
    formatters = cast(dict, config.get("formatters", {}))
    access_formatter = cast(dict, formatters.get("access", {}))
    assert access_formatter.get("()") == "app.core.runtime_logging.UtcAccessFormatter"
    # Restore
    get_settings.cache_clear()


def test_build_log_config_exposes_app_loggers_via_root_handler(monkeypatch):
    from typing import cast

    monkeypatch.setenv("CODEX_LB_LOG_FORMAT", "text")
    from app.core.config.settings import get_settings

    get_settings.cache_clear()
    config = build_log_config()
    root_logger = cast(dict, config.get("root", {}))

    assert root_logger.get("handlers") == ["default"]
    assert root_logger.get("level") == "INFO"
    get_settings.cache_clear()


# --- rendered-record redaction backstop -------------------------------------


_PROXY_AUTHORITY = "183.110.26.193:6014"


def _connection_key_line(proxy_url: str) -> str:
    # Exact shape uvloop's default exception handler logs for aiohttp
    # Connection.__del__ (evidence: prod 'Unclosed connection' ERROR lines).
    return (
        "Unclosed connection\n"
        "client_connection: Connection<ConnectionKey(host='chatgpt.com', port=443, is_ssl=True, ssl=True, "
        f"proxy=URL('{proxy_url}'), proxy_auth=None, proxy_headers_hash=None, server_hostname=None)>"
    )


def _formatter_from_config(monkeypatch, log_format: str, name: str = "default") -> logging.Formatter:
    import importlib
    from typing import cast

    from app.core.config.settings import get_settings

    monkeypatch.setenv("CODEX_LB_LOG_FORMAT", log_format)
    get_settings.cache_clear()
    try:
        spec = dict(cast(dict, cast(dict, build_log_config()["formatters"])[name]))
    finally:
        get_settings.cache_clear()
    module_name, _, class_name = spec.pop("()").rpartition(".")
    return getattr(importlib.import_module(module_name), class_name)(**spec)


def _render(formatter: logging.Formatter, record: logging.LogRecord) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    handler.handle(record)
    return stream.getvalue()


def _record(msg: str, *, level: int = logging.ERROR, name: str = "asyncio", exc_info=None) -> logging.LogRecord:
    return logging.LogRecord(name, level, "connector.py", 1, msg, (), exc_info)


@pytest.mark.parametrize("log_format", ["text", "json"])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_rendered_unclosed_connection_line_redacts_proxy_userinfo(monkeypatch, log_format, scheme):
    formatter = _formatter_from_config(monkeypatch, log_format)
    proxy_url = runtime_basic_auth_url("smart-user", "SECRETPW", _PROXY_AUTHORITY).replace("http://", f"{scheme}://", 1)

    output = _render(formatter, _record(_connection_key_line(proxy_url)))

    assert "SECRETPW" not in output
    assert f"[REDACTED]@{_PROXY_AUTHORITY}" in output
    assert "Unclosed connection" in output
    if log_format == "json":
        assert json.loads(output)["message"] == _connection_key_line(f"{scheme}://[REDACTED]@{_PROXY_AUTHORITY}")


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_rendered_basic_auth_repr_redacts_password(monkeypatch, log_format):
    formatter = _formatter_from_config(monkeypatch, log_format)
    line = _connection_key_line(f"http://{_PROXY_AUTHORITY}").replace(
        "proxy_auth=None",
        "proxy_auth=BasicAuth(login='smart-user', password='SECRETPW', encoding='latin1')",
    )

    output = _render(formatter, _record(line))

    assert "SECRETPW" not in output
    assert "password=[REDACTED], encoding='latin1'" in output


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_rendered_exception_traceback_redacts_userinfo(monkeypatch, log_format):
    import sys

    formatter = _formatter_from_config(monkeypatch, log_format)
    password = "TRACEPW"  # kept off the raising line so the traceback source cannot echo it
    try:
        raise RuntimeError(runtime_basic_auth_url("u", password, "h") + "/")
    except RuntimeError:
        record = _record("request failed", name="app.core.clients.codex", exc_info=sys.exc_info())

    output = _render(formatter, record)

    assert "TRACEPW" not in output
    assert "RuntimeError: http://[REDACTED]@h/" in output


def test_redact_rendered_log_text_never_throws(monkeypatch, text_formatter):
    class _Exploding:
        def sub(self, *args, **kwargs):
            raise RuntimeError("regex engine failure")

    monkeypatch.setattr(runtime_logging, "_USERINFO_PATTERN", _Exploding())
    line = _connection_key_line(runtime_basic_auth_url("u", "pw", _PROXY_AUTHORITY))

    assert runtime_logging.redact_rendered_log_text(line) == line
    assert _render(text_formatter, _record(line)).endswith(line + "\n")


def test_credential_free_info_line_skips_regex_passes(monkeypatch, text_formatter):
    calls: list[str] = []

    class _Spy:
        def sub(self, *args, **kwargs):
            calls.append("userinfo")
            raise AssertionError("precheck must short-circuit")

    monkeypatch.setattr(runtime_logging, "_USERINFO_PATTERN", _Spy())
    monkeypatch.setattr(runtime_logging, "_redact_secret_patterns", lambda text: calls.append("keyed") or text)
    line = ("http_bridge_forward request_id=req_1 max_output_tokens=32768 route_mode=account_bound status=200 " * 6)[
        :500
    ]

    output = _render(text_formatter, _record(line, level=logging.INFO, name="app.modules.proxy"))

    assert line in output
    assert calls == []


def test_warning_records_apply_keyed_secret_patterns(text_formatter):
    output = _render(text_formatter, _record("refresh failed password=SECRETPW code=401", level=logging.WARNING))

    assert "SECRETPW" not in output
    assert "password=[REDACTED] code=401" in output


def test_authorization_midline_redaction_truncates_to_separator(text_formatter):
    # Pins the existing pattern-2 behavior: the redaction consumes the rest of
    # the line up to ',' or '&', so trailing fields on the same line are lost.
    output = _render(text_formatter, _record("upstream rejected Authorization: Basic dXNlcjpwYXNz status=failed"))

    assert "dXNlcjpwYXNz" not in output
    assert output.endswith("upstream rejected Authorization: [REDACTED]\n")
    assert "status=failed" not in output


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_bootstrap_token_output_is_byte_identical_through_redaction(monkeypatch, log_format):
    from app.core.bootstrap import log_bootstrap_token

    formatter = _formatter_from_config(monkeypatch, log_format)
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("tests.bootstrap_token_redaction")
    logger.propagate = False
    logger.addHandler(handler := _Capture())
    try:
        log_bootstrap_token(logger, "bt_0123456789abcdefTOKENVALUE")
    finally:
        logger.removeHandler(handler)
    (record,) = records

    redacted_output = _render(formatter, record)
    monkeypatch.setattr(runtime_logging, "redact_rendered_log_text", lambda text, **kwargs: text)
    plain_output = _render(formatter, record)

    assert "bt_0123456789abcdefTOKENVALUE" in redacted_output
    if log_format == "json":
        # JsonFormatter stamps datetime.now() per call; compare everything else.
        redacted_entry, plain_entry = (json.loads(output) for output in (redacted_output, plain_output))
        assert redacted_entry.pop("timestamp") and plain_entry.pop("timestamp")
        assert redacted_entry == plain_entry
    else:
        assert redacted_output == plain_output


def test_json_formatter_redacts_extras_and_nested_values(json_formatter):
    record = _record("upstream failure", name="app.core.clients.codex")
    record.proxy_url = runtime_basic_auth_url("u", "EXTRAPW", "proxy.test:1")
    record.details = {"urls": [runtime_basic_auth_url("u", "NESTEDPW", "proxy.test:2")], "password": "PLAINPW"}

    class _Unserializable:
        def __repr__(self) -> str:
            return "<Conn " + runtime_basic_auth_url("u", "REPRPW", "proxy.test:3") + ">"

    record.connection = _Unserializable()

    parsed = json.loads(json_formatter.format(record))

    assert parsed["proxy_url"] == "http://[REDACTED]@proxy.test:1"
    assert parsed["details"]["urls"] == ["http://[REDACTED]@proxy.test:2"]
    assert parsed["connection"] == "<Conn http://[REDACTED]@proxy.test:3>"
    for secret in ("EXTRAPW", "NESTEDPW", "REPRPW"):
        assert secret not in json.dumps(parsed)


def test_json_access_formatter_redacts_request_line():
    record = _record("", level=logging.INFO, name="uvicorn.access")
    record.client_addr = "10.0.0.5:1234"
    record.request_line = "GET /probe?target=" + runtime_basic_auth_url("u", "ACCESSPW", "h") + " HTTP/1.1"
    record.status_code = 200

    parsed = json.loads(JsonAccessFormatter().format(record))

    assert "ACCESSPW" not in parsed["request"]
    assert parsed["request"] == "GET /probe?target=http://[REDACTED]@h HTTP/1.1"
    assert parsed["client"] == "10.0.0.5:1234"


def test_text_access_formatter_redacts_request_line():
    formatter = UtcAccessFormatter(
        fmt='%(asctime)s %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        use_colors=None,
    )
    record = _record('%s - "%s %s HTTP/%s" %d', level=logging.INFO, name="uvicorn.access")
    record.args = ("10.0.0.5:1234", "GET", "/probe?target=" + runtime_basic_auth_url("u", "ACCESSPW", "h"), "1.1", 200)

    output = formatter.format(record)

    assert "ACCESSPW" not in output
    assert "http://[REDACTED]@h" in output


def test_redact_log_value_masks_url_userinfo():
    value = "proxy " + runtime_basic_auth_url("user", "secret-pw", "proxy.test:8080") + "/path failed"

    assert _redact_log_value(value) == "proxy http://[REDACTED]@proxy.test:8080/path failed"


def test_redact_rendered_log_text_leaves_plain_email_addresses_alone():
    line = "notify owner ops@example.com about https://status.example.com/incident"

    assert runtime_logging.redact_rendered_log_text(line) == line
