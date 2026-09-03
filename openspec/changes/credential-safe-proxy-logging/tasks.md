## 1. Credentials out of aiohttp repr surfaces

- [x] 1.1 Add `ResolvedProxyEndpoint.aiohttp_proxy_kwargs()` (credential-free
  `proxy` + latin1 `Proxy-Authorization` header) and use it for routed aiohttp
  requests and websocket connects; reserve `proxy_headers` from callers
- [x] 1.2 Fail closed for credentialed aiohttp routes to non-TLS targets and
  for usernames containing `:` at the resolver
- [x] 1.3 Pin byte-identical CONNECT header, credential-free `ConnectionKey`
  repr and `ClientHttpProxyError` text with a fake CONNECT proxy

## 2. Rendered log redaction backstop

- [x] 2.1 Add never-throwing `redact_rendered_log_text` with URL userinfo
  pattern and cheap prechecks; fold userinfo into `_redact_log_value`
- [x] 2.2 Apply to text, access, and JSON formatters (message, exception,
  extras); route `warnings.warn` through logging at server start
- [x] 2.3 Regression tests: exact production line (text and JSON), `https`
  variant, `BasicAuth` repr, exception traceback, never-throws, precheck
  short-circuit, bootstrap token byte-identity, mid-line `Authorization:`

## 3. Loop exception handler

- [x] 3.1 Add idempotent `install_redacting_loop_exception_handler` that
  redacts context reprs and delegates to the previous/default handler
- [x] 3.2 Install once at lifespan start; test byte-identical output for
  secret-free contexts under asyncio and uvloop

## 4. Direct websocket InvalidProxy hardening

- [x] 4.1 Use the fixed credential-safe message for `InvalidProxy` under
  every policy; log only the URL-free reason
- [x] 4.2 Update the Responses `InvalidProxy` test and the realtime spec

## 5. Verification

- [x] 5.1 Run focused unit tests, ruff, ty, proxy architecture check
- [x] 5.2 Run strict scoped OpenSpec validation
