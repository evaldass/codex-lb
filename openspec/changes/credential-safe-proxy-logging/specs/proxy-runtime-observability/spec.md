## ADDED Requirements

### Requirement: Rendered log records redact URL userinfo and keyed secrets

Every log record rendered by the application's text, access, and JSON
formatters MUST have `scheme://user:password@` URL userinfo replaced with
`scheme://[REDACTED]@` and canonical `Basic <token>` authorization tokens
(a reversible encoding of `user:password`, as carried in aiohttp proxy-error
reprs) replaced with `Basic [REDACTED]`, regardless of the originating logger
(application, `asyncio`, aiohttp, uvicorn) and including exception and stack
text. Structured extra keys MUST be redacted like values. Records at WARNING
level or higher MUST additionally have keyed secrets (`password=`, `token=`,
`api_key=`, bearer, basic and authorization values in any letter case, JSON
secret fields embedded in strings, and structured extra fields whose key names
a secret, whatever the value type) redacted. Redaction MUST never raise: on
failure the record is emitted unchanged, and structured extras that are cyclic,
pathologically deep, or unprintable MUST still be emitted with redaction
applied to every finite, printable part. Application startup MUST install an asyncio loop exception
handler that redacts the `repr()` of context values before the default
handler logs them, MUST leave secret-free context output byte-identical to
the default handler, and MUST route `warnings.warn` output through the same
log handlers. Log records that contain no secret patterns MUST render
byte-identically to the unredacted rendering.

#### Scenario: Unclosed aiohttp connection repr is credential-free

- **GIVEN** an aiohttp connection is finalized without release and its connection key holds a credentialed proxy URL
- **WHEN** the loop exception handler logs `Unclosed connection` through the `asyncio` logger
- **THEN** the rendered record contains `proxy=URL('scheme://[REDACTED]@host:port')`
- **AND** the password appears in neither the text nor the JSON rendering

#### Scenario: Proxy error repr with a Basic token is masked

- **GIVEN** an aiohttp proxy error whose tunnel request headers carry `Proxy-Authorization: Basic <token>`
- **WHEN** the error is logged with `%r` at any level, or its repr reaches the loop exception handler through an unretrieved task
- **THEN** the rendered record contains `'Proxy-Authorization': 'Basic [REDACTED]'`
- **AND** neither the token nor the password appears in the text or JSON rendering

#### Scenario: Secret-keyed structured extras are masked

- **GIVEN** a WARNING or higher record carries an extra field such as `{"password": "..."}` or `{"access_token": "..."}`
- **WHEN** the JSON formatter renders the record
- **THEN** the field value is replaced with `[REDACTED]` whatever its type (string, list, number, bytes, mapping); a null value stays null
- **AND** fields such as `attempt` or `tokens` keep their values
- **AND** an extra key carrying URL userinfo is rendered as `scheme://[REDACTED]@host`

#### Scenario: Secret-free records are unchanged

- **WHEN** a record such as the one-time bootstrap token banner contains no URL userinfo or keyed secret pattern
- **THEN** the rendered output is byte-identical to the unredacted rendering
- **AND** the loop exception handler output for a secret-free context is byte-identical to the default handler output

#### Scenario: Redaction failure never breaks logging

- **WHEN** the redaction pattern raises while rendering a record
- **THEN** the record is emitted with its original text

#### Scenario: Cyclic or unprintable structured extras never drop the record

- **GIVEN** a record carries an extra whose container refers back to itself, or whose `repr()` raises
- **WHEN** the JSON formatter renders the record
- **THEN** the record is emitted, the back-reference collapses to a `{...}` / `[...]` placeholder and the unprintable value to an `<unprintable ...>` marker
- **AND** secret-keyed fields and URL userinfo in the finite part of the extra are still redacted
