# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an implementation of ``FetcherInterface`` using the httpx HTTP
library.

Note that this module is an optional fetcher, and the default fetcher is
Urllib3Fetcher:
* If HttpxFetcher is used, note that `httpx` must be explicitly
  depended on: python-tuf does not do that.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib import parse

# Imports
import httpx

import tuf
from tuf.api import exceptions
from tuf.ngclient.fetcher import FetcherInterface

if TYPE_CHECKING:
    from collections.abc import Iterator

# Globals
logger = logging.getLogger(__name__)


# Classes
class HttpxFetcher(FetcherInterface):
    """An implementation of ``FetcherInterface`` based on the httpx library.
    It supports HTTP/2 if httpx[http2] is installed.

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
        http2: bool = False,
    ) -> None:
        # NOTE: We use a separate httpx.Client per scheme+hostname
        # combination, in order to reuse connections to the same hostname to
        # improve efficiency, but avoiding sharing state between different
        # hosts-scheme combinations to minimize subtle security issues.
        # Some cookies may not be HTTP-safe.
        self._sessions: dict[tuple[str, str], httpx.Client] = {}

        # Default settings
        self.socket_timeout: int = socket_timeout  # seconds
        self.chunk_size: int = chunk_size  # bytes
        self.app_user_agent = app_user_agent
        self.http2 = http2

    def _fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS url from a remote server.

        Args:
            url: URL string that represents a file location.

        Raises:
            exceptions.SlowRetrievalError: Timeout occurs while receiving
                data.
            exceptions.DownloadHTTPError: HTTP error code is received.

        Returns:
            Bytes iterator
        """
        # Get a customized session for each new schema+hostname combination.
        session = self._get_session(url)

        # Get the httpx.Response object for this URL.
        try:
            # Use stream to defer downloading the response body
            # httpx Client manages the stream context, but we will yield from it.
            # However, httpx stream() requires context manager.
            # For FetcherInterface, we must return an iterator.
            # We will use httpx's stream context manager internally.
            pass
        except httpx.TimeoutException as e:
            raise exceptions.SlowRetrievalError from e

        return self._chunks(session, url)

    def _chunks(self, session: httpx.Client, url: str) -> Iterator[bytes]:
        """A generator function to be returned by fetch."""

        try:
            with session.stream(
                "GET", url, timeout=self.socket_timeout
            ) as response:
                try:
                    response.raise_for_status()
                except httpx.HTTPStatusError as e:
                    status = e.response.status_code
                    raise exceptions.DownloadHTTPError(str(e), status) from e

                try:
                    yield from response.iter_bytes(self.chunk_size)
                except httpx.TimeoutException as e:
                    raise exceptions.SlowRetrievalError from e
                except httpx.RequestError as e:
                    raise exceptions.DownloadError(str(e)) from e
        except httpx.TimeoutException as e:
            raise exceptions.SlowRetrievalError from e
        except httpx.RequestError as e:
            raise exceptions.DownloadError(str(e)) from e

    def _get_session(self, url: str) -> httpx.Client:
        """Return a different customized httpx.Client per schema+hostname
        combination.

        Raises:
            exceptions.DownloadError: When there is a problem parsing the url.
        """
        parsed_url = parse.urlparse(url)

        if not parsed_url.scheme:
            raise exceptions.DownloadError(f"Failed to parse URL {url}")

        session_index = (parsed_url.scheme, parsed_url.hostname or "")
        session = self._sessions.get(session_index)

        if not session:
            # Build User-Agent
            ua = f"python-tuf/{tuf.__version__} httpx/{httpx.__version__}"
            if self.app_user_agent is not None:
                ua = f"{self.app_user_agent} {ua}"

            session = httpx.Client(http2=self.http2, headers={"User-Agent": ua})
            self._sessions[session_index] = session

            logger.debug("Made new session %s", session_index)
        else:
            logger.debug("Reusing session %s", session_index)

        return session
