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
opened. Route resolution MUST fail closed for a proxy username containing `:`.
Native egress and SOCKS transports keep their existing credential handling.

#### Scenario: Credentialed https endpoint uses Proxy-Authorization

- **GIVEN** a resolved `https` proxy endpoint with a username and password
- **WHEN** the Codex upstream client sends a routed request or opens a routed WebSocket through aiohttp
- **THEN** the aiohttp `proxy` argument contains no userinfo
- **AND** the CONNECT request carries a `Proxy-Authorization` header byte-identical to the userinfo-derived token
- **AND** aiohttp connection-key and proxy-error text contain neither the password nor its Basic token

#### Scenario: Credentialed route to a plaintext target fails closed

- **GIVEN** a resolved proxy endpoint with credentials
- **WHEN** the Codex upstream client is asked to reach an `http` or `ws` upstream URL through aiohttp
- **THEN** the client fails before dispatch with a credential-free error

#### Scenario: Username with a colon is rejected at resolution

- **WHEN** a proxy endpoint username contains `:`
- **THEN** route resolution fails closed with reason `invalid_proxy_username`
