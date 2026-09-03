from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from aiohttp import encode_basic_auth

_PLAINTEXT_SCHEMES = frozenset({"http", "socks5", "socks5h"})


@dataclass(frozen=True, slots=True)
class ResolvedProxyEndpoint:
    id: str
    scheme: str
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    def _reject_plaintext_credentials(self) -> None:
        if self.scheme.lower() in _PLAINTEXT_SCHEMES and (self.username is not None or self.password is not None):
            raise ValueError("credential-bearing plaintext proxy URLs are forbidden")

    @property
    def proxy_url(self) -> str:
        self._reject_plaintext_credentials()
        scheme = "socks5h" if self.scheme == "socks5" else self.scheme
        auth = ""
        if self.username:
            auth = f"{quote(self.username, safe='')}:{quote(self.password or '', safe='')}@"
        return f"{scheme}://{auth}{self.host}:{self.port}"

    @property
    def proxy_url_without_credentials(self) -> str:
        scheme = "socks5h" if self.scheme == "socks5" else self.scheme
        return f"{scheme}://{self.host}:{self.port}"

    def aiohttp_proxy_kwargs(self) -> dict[str, Any]:
        """Return ``proxy``/``proxy_headers`` kwargs for aiohttp request and ws_connect.

        Credentials travel in a ``Proxy-Authorization`` header instead of URL
        userinfo so aiohttp's ``ConnectionKey``/``Connection`` reprs and
        ``ClientHttpProxyError.__str__`` never carry the password. ``latin1``
        matches aiohttp's own userinfo encoding (``BasicAuth`` default), so the
        CONNECT header stays byte-identical. aiohttp forwards ``proxy_headers``
        only on the CONNECT tunnel request, i.e. for TLS (``https``/``wss``)
        targets; callers must not use these kwargs for plaintext targets.
        """
        self._reject_plaintext_credentials()
        kwargs: dict[str, Any] = {"proxy": self.proxy_url_without_credentials}
        if self.username:
            kwargs["proxy_headers"] = {
                "Proxy-Authorization": encode_basic_auth(self.username, self.password or "", encoding="latin1"),
            }
        return kwargs


@dataclass(frozen=True, slots=True)
class ResolvedUpstreamRoute:
    mode: str
    pool_id: str
    endpoint: ResolvedProxyEndpoint
    fallbacks: tuple[ResolvedProxyEndpoint, ...] = ()

    @property
    def endpoint_id(self) -> str:
        return self.endpoint.id

    @property
    def proxy_url(self) -> str:
        return self.endpoint.proxy_url

    def with_endpoint(
        self,
        endpoint: ResolvedProxyEndpoint,
        fallbacks: tuple[ResolvedProxyEndpoint, ...],
    ) -> "ResolvedUpstreamRoute":
        return ResolvedUpstreamRoute(self.mode, self.pool_id, endpoint, fallbacks)
