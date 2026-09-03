## ADDED Requirements

### Requirement: Routed aiohttp egress carries proxy credentials outside the proxy URL

When the Codex upstream client dispatches a routed HTTP request or WebSocket
connect through aiohttp, it MUST pass a credential-free proxy URL
(`scheme://host:port`) and MUST carry the endpoint username and password as a
`Proxy-Authorization` Basic header whose bytes are identical to the header
aiohttp derives from URL userinfo (latin1 encoding). The client MUST NOT place
proxy credentials in the aiohttp proxy URL. Because aiohttp forwards proxy
headers only on the CONNECT tunnel, a credentialed aiohttp route MUST fail
closed for a non-TLS (`http`/`ws`) upstream target before any connection is
opened, for every endpoint in the ordered pool, so a credential-free fallback
endpoint cannot absorb the misconfigured primary. Route resolution MUST fail
closed for a proxy username containing `:`; the dashboard MUST reject such a
username at endpoint creation, and the endpoint test route MUST report the
resolver reason as a failed probe rather than an unhandled error. Native egress
and SOCKS transports keep their existing credential handling.

#### Scenario: Credentialed https endpoint uses Proxy-Authorization

- **GIVEN** a resolved `https` proxy endpoint with a username and password
- **WHEN** the Codex upstream client sends a routed request or opens a routed WebSocket through aiohttp
- **THEN** the aiohttp `proxy` argument contains no userinfo
- **AND** the CONNECT request carries a `Proxy-Authorization` header byte-identical to the userinfo-derived token
- **AND** aiohttp connection-key and proxy-error text contain neither the password nor its Basic token

#### Scenario: Credentialed route to a plaintext target fails closed

- **GIVEN** a resolved route whose primary proxy endpoint carries credentials and whose fallback does not
- **WHEN** the Codex upstream client is asked to reach an `http` or `ws` upstream URL through aiohttp, for an idempotent or non-idempotent request or a WebSocket open
- **THEN** the client fails before dispatch with a credential-free error
- **AND** no endpoint in the pool, including the credential-free fallback, receives the request

#### Scenario: Username with a colon is rejected at resolution

- **WHEN** a proxy endpoint username contains `:`
- **THEN** route resolution fails closed with reason `invalid_proxy_username`

#### Scenario: Dashboard rejects and reports colon usernames

- **WHEN** an operator creates an upstream proxy endpoint whose username contains `:`
- **THEN** the request is rejected with a 400 error coded `invalid_proxy_username`
- **WHEN** the endpoint test route is invoked for an already persisted endpoint the resolver rejects
- **THEN** the response reports `ok: false` with the resolver reason as `error`
