# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an implementation of ``FetcherInterface`` using the urllib3 HTTP
library.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import suppress
from typing import TYPE_CHECKING

# Imports
import urllib3

import tuf
from tuf.api import exceptions
from tuf.ngclient._internal.proxy import ProxyEnvironment
from tuf.ngclient.fetcher import FetcherInterface

if TYPE_CHECKING:
    from collections.abc import Generator

# Globals
logger = logging.getLogger(__name__)


def _discard_response(response: urllib3.response.BaseHTTPResponse) -> None:
    """Close the response before returning its connection to the pool."""
    response.close()
    response.release_conn()


class _ResponseStream(Iterator[bytes]):
    """Own the response until the chunk generator starts reading."""

    def __init__(
        self,
        response: urllib3.response.BaseHTTPResponse,
        chunks: Generator[bytes, None, None],
    ) -> None:
        self._unread_response: urllib3.response.BaseHTTPResponse | None = (
            response
        )
        self._chunks = chunks

    def __next__(self) -> bytes:
        self._unread_response = None
        return next(self._chunks)

    def close(self) -> None:
        response = self._unread_response
        self._unread_response = None
        self._chunks.close()
        if response is not None:
            _discard_response(response)


class Urllib3Fetcher(FetcherInterface):
    """An implementation of ``FetcherInterface`` based on the urllib3 library.

    Attributes:
        socket_timeout: Timeout in seconds, used for both initial connection
            delay and the maximum delay between bytes received.
        chunk_size: Chunk size in bytes used when downloading.
    """

    def __init__(
        self,
        socket_timeout: int = 30,
        chunk_size: int = 400000,
        app_user_agent: str | None = None,
    ) -> None:
        # Default settings
        self.socket_timeout: int = socket_timeout  # seconds
        self.chunk_size: int = chunk_size  # bytes

        # Create User-Agent.
        ua = f"python-tuf/{tuf.__version__}"
        if app_user_agent is not None:
            ua = f"{app_user_agent} {ua}"

        self._proxy_env = ProxyEnvironment(headers={"User-Agent": ua})

    def _fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS url from a remote server.

        Args:
            url: URL string that represents a file location.

        Raises:
            SlowRetrievalError: Timeout occurs while receiving data.
            DownloadHTTPError: HTTP error code is received.

        Returns:
            Bytes iterator
        """

        # Defer downloading the response body with preload_content=False.
        # Always set the timeout. This timeout value is interpreted by
        # urllib3 as:
        #  - connect timeout (max delay before first byte is received)
        #  - read (gap) timeout (max delay between bytes received)
        try:
            response = self._proxy_env.request(
                "GET",
                url,
                preload_content=False,
                timeout=urllib3.Timeout(self.socket_timeout),
            )
        except urllib3.exceptions.MaxRetryError as e:
            if isinstance(e.reason, urllib3.exceptions.TimeoutError):
                raise exceptions.SlowRetrievalError from e
            # Any other reason (e.g. TLS or connection error): let the original
            # error propagate instead of falling through to an unbound response.
            raise

        if response.status >= 400:
            response.close()
            raise exceptions.DownloadHTTPError(
                f"HTTP error occurred with status {response.status}",
                response.status,
            )

        return _ResponseStream(response, self._chunks(response))

    def _chunks(
        self, response: urllib3.response.BaseHTTPResponse
    ) -> Generator[bytes, None, None]:
        """Stream the response body and manage its connection on exit."""
        try:
            yield from response.stream(self.chunk_size)
        except GeneratorExit:
            _discard_response(response)
            raise
        except BaseException as e:
            # Preserve the original failure if discarding the response fails.
            with suppress(Exception):
                _discard_response(response)
            if isinstance(e, urllib3.exceptions.TimeoutError) or (
                isinstance(e, urllib3.exceptions.MaxRetryError)
                and isinstance(e.reason, urllib3.exceptions.TimeoutError)
            ):
                raise exceptions.SlowRetrievalError from e
            raise
        else:
            response.release_conn()
