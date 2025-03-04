# Copyright 2025, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient ProxyEnvironment"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import Mock, patch

from urllib3 import PoolManager, ProxyManager

from tests import utils
from tuf.ngclient._internal.proxy import ProxyEnvironment


class TestProxyEnvironment(unittest.TestCase):
    """Test ngclient ProxyEnvironment implementation

    These tests use the ProxyEnvironment.get_pool_manager() endpoint and then
    look at the ProxyEnvironment._poolmanagers dict keys to decide if the result
    is correct.

    The test environment is changed via mocking getproxies(): this is a urllib
    method that returns a dict with the proxy environment variable contents.

    Testing ProxyEnvironment.request() would possibly be better but far more
    difficult: the current test implementation does not require actually setting up
    all of the different proxies.
    """

    def assert_pool_managers(
        self, env: ProxyEnvironment, expected: list[str | None]
    ) -> None:
        # Pool managers have the expected proxy urls
        self.assertEqual(list(env._pool_managers.keys()), expected)

        # Pool manager types are as expected
        for proxy_url, pool_manager in env._pool_managers.items():
            self.assertIsInstance(pool_manager, PoolManager)
            if proxy_url is not None:
                self.assertIsInstance(pool_manager, ProxyManager)

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_no_variables(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {}

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "subdomain.example.com")
        env.get_pool_manager("https", "differentsite.com")

        # There is a single pool manager (no proxies)
        self.assert_pool_managers(env, [None])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_proxy_set(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "https": "http://localhost:8888",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "differentsite.com")

        # There are two pool managers: A plain poolmanager and https proxymanager
        self.assert_pool_managers(env, [None, "http://localhost:8888"])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_proxies_set(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "http": "http://localhost:8888",
            "https": "http://localhost:9999",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "subdomain.example.com")
        env.get_pool_manager("https", "differentsite.com")

        # There are two pool managers: A http proxymanager and https proxymanager
        self.assert_pool_managers(
            env, ["http://localhost:8888", "http://localhost:9999"]
        )

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_no_proxy_set(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "http": "http://localhost:8888",
            "https": "http://localhost:9999",
            "no": "somesite.com, example.com, another.site.com",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")

        # There is a single pool manager (no proxies)
        self.assert_pool_managers(env, [None])

        env.get_pool_manager("http", "differentsite.com")
        env.get_pool_manager("https", "differentsite.com")

        # There are three pool managers: plain poolmanager for no_proxy domains,
        # http proxymanager and https proxymanager
        self.assert_pool_managers(
            env, [None, "http://localhost:8888", "http://localhost:9999"]
        )

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_no_proxy_subdomain_match(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "https": "http://localhost:9999",
            "no": "somesite.com, example.com, another.site.com",
        }

        env = ProxyEnvironment()

        # this should match example.com in no_proxy
        env.get_pool_manager("https", "subdomain.example.com")

        # There is a single pool manager (no proxies)
        self.assert_pool_managers(env, [None])

        # this should not match example.com in no_proxy
        env.get_pool_manager("https", "xexample.com")

        # There are two pool managers: plain poolmanager for no_proxy domains,
        # and a https proxymanager
        self.assert_pool_managers(env, [None, "http://localhost:9999"])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_no_proxy_wildcard(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "https": "http://localhost:8888",
            "no": "*",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "differentsite.com")
        env.get_pool_manager("https", "subdomain.example.com")

        # There is a single pool manager, no proxies
        self.assert_pool_managers(env, [None])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_no_proxy_leading_dot(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "https": "http://localhost:8888",
            "no": ".example.com",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "subdomain.example.com")

        # There is a single pool manager, no proxies
        self.assert_pool_managers(env, [None])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_all_proxy_set(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "all": "http://localhost:8888",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "subdomain.example.com")
        env.get_pool_manager("https", "differentsite.com")

        # There is a single proxy manager
        self.assert_pool_managers(env, ["http://localhost:8888"])

        # This urllib3 currently only handles http and https but let's test anyway
        env.get_pool_manager("file", None)

        # proxy manager and a plain pool manager
        self.assert_pool_managers(env, ["http://localhost:8888", None])

    @patch("tuf.ngclient._internal.proxy.getproxies")
    def test_all_proxy_and_no_proxy_set(self, mock_getproxies: Mock) -> None:
        mock_getproxies.return_value = {
            "all": "http://localhost:8888",
            "no": "somesite.com, example.com, another.site.com",
        }

        env = ProxyEnvironment()
        env.get_pool_manager("http", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "example.com")
        env.get_pool_manager("https", "subdomain.example.com")

        # There is a single pool manager (no proxies)
        self.assert_pool_managers(env, [None])

        env.get_pool_manager("http", "differentsite.com")
        env.get_pool_manager("https", "differentsite.com")

        # There are two pool managers: plain poolmanager for no_proxy domains and
        # one proxymanager
        self.assert_pool_managers(env, [None, "http://localhost:8888"])


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
