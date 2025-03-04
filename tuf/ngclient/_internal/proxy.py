# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Proxy environment variable handling with Urllib3"""

from __future__ import annotations

from typing import Any
from urllib.request import getproxies

from urllib3 import BaseHTTPResponse, PoolManager, ProxyManager
from urllib3.util.url import parse_url


# TODO: ProxyEnvironment could implement the whole PoolManager.RequestMethods
# Mixin: We only need request() so nothing else is currently implemented
class ProxyEnvironment:
    """A PoolManager manager for automatic proxy handling based on env variables

    Keeps track of PoolManagers for different proxy urls based on proxy
    environment variables. Use `get_pool_manager()` or `request()` to access
    the right manager for a scheme/host.

    Supports '*_proxy' variables, with special handling for 'no_proxy' and
    'all_proxy'.
    """

    def __init__(
        self,
        **kw_args: Any,  # noqa: ANN401
    ) -> None:
        self._pool_managers: dict[str | None, PoolManager] = {}
        self._kw_args = kw_args

        self._proxies = getproxies()
        self._all_proxy = self._proxies.pop("all", None)
        no_proxy = self._proxies.pop("no", None)
        if no_proxy is None:
            self._no_proxy_hosts = []
        else:
            # split by comma, remove leading periods
            self._no_proxy_hosts = [
                h.lstrip(".") for h in no_proxy.replace(" ", "").split(",") if h
            ]

    def _get_proxy(self, scheme: str | None, host: str | None) -> str | None:
        """Get a proxy url for scheme and host based on proxy env variables"""

        if host is None:
            # urllib3 only handles http/https but we can do something reasonable
            # even for schemes that don't require host (like file)
            return None

        # does host match any of the "no_proxy" hosts?
        for no_proxy_host in self._no_proxy_hosts:
            # wildcard match, exact hostname match, or parent domain match
            if no_proxy_host in ("*", host) or host.endswith(
                f".{no_proxy_host}"
            ):
                return None

        if scheme in self._proxies:
            return self._proxies[scheme]
        if self._all_proxy is not None:
            return self._all_proxy

        return None

    def get_pool_manager(
        self, scheme: str | None, host: str | None
    ) -> PoolManager:
        """Get a poolmanager for scheme and host.

        Returns a ProxyManager if that is correct based on current proxy env
        variables, otherwise returns a PoolManager
        """

        proxy = self._get_proxy(scheme, host)
        if proxy not in self._pool_managers:
            if proxy is None:
                self._pool_managers[proxy] = PoolManager(**self._kw_args)
            else:
                self._pool_managers[proxy] = ProxyManager(
                    proxy,
                    **self._kw_args,
                )

        return self._pool_managers[proxy]

    def request(
        self,
        method: str,
        url: str,
        **request_kw: Any,  # noqa: ANN401
    ) -> BaseHTTPResponse:
        """Make a request using a PoolManager chosen based on url and
        proxy environment variables.
        """
        u = parse_url(url)
        manager = self.get_pool_manager(u.scheme, u.host)
        return manager.request(method, url, **request_kw)
