from __future__ import annotations

import asyncio
import base64
from urllib.parse import quote

import aiohttp
import pytest
from aiohttp.client_reqrep import ClientRequest
from yarl import URL

from app.core.upstream_proxy import ResolvedProxyEndpoint

pytestmark = pytest.mark.unit

# latin1 non-ASCII so the header encoding is pinned against aiohttp's own
# userinfo path (BasicAuth defaults to latin1; encode_basic_auth to utf-8).
_PASSWORD = "S3cret-P\u00e4ss"
_USERNAME = "smart-user"


def _credentialed_endpoint(host: str = "proxy.test", port: int = 8080) -> ResolvedProxyEndpoint:
    return ResolvedProxyEndpoint("ep_1", "https", host, port, _USERNAME, _PASSWORD)


def test_aiohttp_proxy_kwargs_without_credentials_only_sets_proxy() -> None:
    endpoint = ResolvedProxyEndpoint("ep_1", "https", "proxy.test", 8080)

    assert endpoint.aiohttp_proxy_kwargs() == {"proxy": "https://proxy.test:8080"}
    assert endpoint.proxy_url_without_credentials == endpoint.proxy_url


def test_aiohttp_proxy_kwargs_move_credentials_into_proxy_authorization() -> None:
    kwargs = _credentialed_endpoint().aiohttp_proxy_kwargs()

    assert kwargs["proxy"] == "https://proxy.test:8080"
    assert "@" not in kwargs["proxy"]
    header = kwargs["proxy_headers"]["Proxy-Authorization"]
    # Byte-identical to the token aiohttp derives from ``https://u:p@`` userinfo
    # (BasicAuth.encode: latin1, not encode_basic_auth's utf-8 default).
    assert header == "Basic " + base64.b64encode(f"{_USERNAME}:{_PASSWORD}".encode("latin1")).decode("latin1")
    assert header != aiohttp.encode_basic_auth(_USERNAME, _PASSWORD)


@pytest.mark.parametrize("scheme", ["http", "socks5", "socks5h"])
def test_aiohttp_proxy_kwargs_reject_plaintext_credentials(scheme: str) -> None:
    endpoint = ResolvedProxyEndpoint("ep_1", scheme, "proxy.test", 8080, "u", "p")

    with pytest.raises(ValueError, match="plaintext proxy URLs are forbidden"):
        endpoint.aiohttp_proxy_kwargs()


def test_aiohttp_proxy_kwargs_reject_colon_in_username() -> None:
    endpoint = ResolvedProxyEndpoint("ep_1", "https", "proxy.test", 8080, "user:name", "p")

    with pytest.raises(ValueError):
        endpoint.aiohttp_proxy_kwargs()


def test_socks_kwargs_keep_credential_free_socks5h_url() -> None:
    endpoint = ResolvedProxyEndpoint("ep_1", "socks5", "proxy.test", 1080)

    assert endpoint.aiohttp_proxy_kwargs() == {"proxy": "socks5h://proxy.test:1080"}


@pytest.mark.asyncio
@pytest.mark.parametrize("password", [_PASSWORD, quote(_PASSWORD, safe="")], ids=["raw", "quoted"])
async def test_connection_key_repr_is_credential_free(password: str) -> None:
    endpoint = ResolvedProxyEndpoint("ep_1", "https", "proxy.test", 8080, _USERNAME, password)
    kwargs = endpoint.aiohttp_proxy_kwargs()
    request = ClientRequest(
        "GET",
        URL("https://chatgpt.com/"),
        loop=asyncio.get_running_loop(),
        proxy=URL(kwargs["proxy"]),  # ClientSession performs this URL() wrap
        proxy_headers=kwargs["proxy_headers"],
    )

    rendered = f"Connection<{request.connection_key!r}>"

    assert password not in rendered
    assert _PASSWORD not in rendered
    assert "proxy=URL('https://proxy.test:8080')" in rendered
    assert "proxy_auth=None" in rendered
    # Per-proxy pooling stays keyed through the header hash.
    assert request.connection_key.proxy_headers_hash is not None


class _FakeConnectProxy:
    """Plaintext CONNECT proxy that records request heads and answers 502."""

    def __init__(self) -> None:
        self.heads: list[str] = []
        self._server: asyncio.Server | None = None

    async def __aenter__(self) -> "_FakeConnectProxy":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        self.heads.append(head.decode("latin1"))
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()


def _proxy_authorization(head: str) -> str:
    lines = [line for line in head.split("\r\n") if line.lower().startswith("proxy-authorization:")]
    assert len(lines) == 1, head
    return lines[0].split(":", 1)[1].strip()


@pytest.mark.asyncio
async def test_connect_header_is_byte_identical_and_proxy_error_is_credential_free() -> None:
    async with _FakeConnectProxy() as proxy:
        port = proxy.port
        endpoint = _credentialed_endpoint("127.0.0.1", port)
        kwargs = endpoint.aiohttp_proxy_kwargs()
        # The fake proxy speaks plaintext; only the CONNECT bytes matter here.
        kwargs["proxy"] = kwargs["proxy"].replace("https://", "http://", 1)
        baseline_proxy = f"http://{quote(_USERNAME, safe='')}:{quote(_PASSWORD, safe='')}@127.0.0.1:{port}"

        async with aiohttp.ClientSession() as session:
            with pytest.raises(aiohttp.ClientHttpProxyError):
                await session.get("https://chatgpt.com/", proxy=baseline_proxy)
            with pytest.raises(aiohttp.ClientHttpProxyError) as exc_info:
                await session.get("https://chatgpt.com/", **kwargs)

    assert len(proxy.heads) == 2
    assert all(head.startswith("CONNECT chatgpt.com:443 HTTP/1.1\r\n") for head in proxy.heads)
    baseline_header, header = (_proxy_authorization(head) for head in proxy.heads)
    assert header == baseline_header == kwargs["proxy_headers"]["Proxy-Authorization"]

    message = str(exc_info.value)
    assert _PASSWORD not in message
    assert quote(_PASSWORD, safe="") not in message
    assert header.removeprefix("Basic ") not in message
    assert f"http://127.0.0.1:{port}" in message
