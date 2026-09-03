## Why

Production logs show `ERROR asyncio Unclosed connection` lines whose aiohttp
`ConnectionKey` repr embeds the routed proxy URL with the plaintext proxy
password. The Codex upstream client passes the credential-bearing proxy URL
to aiohttp, which stores it verbatim in the connection pool key and renders it
in `Connection.__repr__` and `ClientHttpProxyError.__str__`; the loop's default
exception handler then logs that repr through the `asyncio` logger, and none
of the application log formatters redact URL userinfo. The direct websocket
path also forwards `websockets.InvalidProxy` text (full proxy URL) to API
clients under the Responses policy.

## What Changes

- Routed aiohttp requests and websocket connects carry proxy credentials in a
  `Proxy-Authorization` header (latin1 Basic token, byte-identical to the one
  aiohttp derives from URL userinfo) and a credential-free proxy URL, so
  aiohttp repr surfaces never contain the password. Credentialed aiohttp routes
  require a TLS (`https`/`wss`) upstream target because aiohttp forwards proxy
  headers only on the CONNECT tunnel; plaintext targets fail closed. The
  resolver rejects usernames containing `:` (not encodable as Basic
  credentials). Native egress and SOCKS transports keep their existing fields.
- Every rendered log record (text and JSON formatters, any logger) masks
  `scheme://user:pass@` userinfo; WARNING-and-higher records additionally get
  the existing keyed/bearer/authorization/JSON secret patterns. Redaction never
  raises. `log_error_response` also masks URL userinfo. The server entrypoint
  routes `warnings.warn` output through the same handlers.
- The application installs a redacting asyncio loop exception handler at
  lifespan start so object reprs (`ConnectionKey`, `BasicAuth`, task
  exceptions) are masked before the default handler renders them.
- The direct websocket connector returns the fixed credential-safe message for
  `InvalidProxy` under every policy (Responses included) and logs only the
  URL-free reason.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `upstream-proxy-routing`: aiohttp routed egress MUST carry proxy credentials
  in `Proxy-Authorization`, never URL userinfo; credentialed aiohttp routes
  MUST require a TLS target.
- `proxy-runtime-observability`: rendered log records and loop exception
  handler output MUST redact URL userinfo and keyed secrets regardless of the
  originating logger.
- `realtime-api-compat`: the Responses websocket `InvalidProxy` message is now
  the same fixed credential-safe message as the live sideband.

## Impact

- Code: `app/core/upstream_proxy/types.py`, `app/core/upstream_proxy/resolver.py`,
  `app/core/clients/codex.py`, `app/core/runtime_logging.py`, `app/main.py`,
  `app/cli.py`, `app/core/clients/proxy_websocket.py`.
- Tests: `tests/unit/test_upstream_proxy_types.py` (new),
  `tests/unit/test_runtime_logging_loop_handler.py` (new),
  `tests/unit/test_codex_client.py`, `tests/unit/test_structured_logging.py`,
  `tests/unit/test_upstream_proxy_resolver.py`,
  `tests/unit/test_proxy_websocket_client.py`, `tests/unit/test_cli.py`.
- Wire compatibility: identical CONNECT `Proxy-Authorization` bytes, identical
  per-proxy connection pooling (keyed through `proxy_headers_hash`), no
  forwarded payload change. INFO-level log records cost ~1 us more to render.
- No settings, dependencies, schemas, routes, database, or frontend changes.
