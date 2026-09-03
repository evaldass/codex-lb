## ADDED Requirements

### Requirement: Rendered log records redact URL userinfo and keyed secrets

Every log record rendered by the application's text, access, and JSON
formatters MUST have `scheme://user:password@` URL userinfo replaced with
`scheme://[REDACTED]@`, regardless of the originating logger (application,
`asyncio`, aiohttp, uvicorn) and including exception and stack text. Records
at WARNING level or higher MUST additionally have keyed secrets
(`password=`, `token=`, `api_key=`, bearer and authorization values, JSON
secret fields) redacted. Redaction MUST never raise; on failure the record is
emitted unchanged. Application startup MUST install an asyncio loop exception
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

#### Scenario: Secret-free records are unchanged

- **WHEN** a record such as the one-time bootstrap token banner contains no URL userinfo or keyed secret pattern
- **THEN** the rendered output is byte-identical to the unredacted rendering
- **AND** the loop exception handler output for a secret-free context is byte-identical to the default handler output

#### Scenario: Redaction failure never breaks logging

- **WHEN** the redaction pattern raises while rendering a record
- **THEN** the record is emitted with its original text
