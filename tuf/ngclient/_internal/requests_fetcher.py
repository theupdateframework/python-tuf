# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an implementation of ``FetcherInterface`` using the Requests HTTP
library.
"""

# requests_fetcher is public but comes from _internal for now (because
# sigstore-python 1.0 still uses the module from there). requests_fetcher
# can be moved out of _internal once sigstore-python 1.0 is not relevant.

import logging
from typing import Dict, Iterator, Optional, Tuple
from urllib import parse

# Imports
import requests

import tuf
from tuf.api import exceptions
from tuf.ngclient.fetcher import FetcherInterface

# Globals
logger = logging.getLogger(__name__)


# Classes
class RequestsFetcher(FetcherInterface):
    """An implementation of ``FetcherInterface`` based on the requests library.

    Attributes:
        socket_timeout: Timeout in seconds, used for both initial connection
            delay and the maximum delay between bytes received.
        chunk_size: Chunk size in bytes used when downloading.
    """

    def __init__(
        self,
        socket_timeout: int = 30,
        chunk_size: int = 400000,
        app_user_agent: Optional[str] = None,
    ) -> None:
        # http://docs.python-requests.org/en/master/user/advanced/#session-objects:
        #
        # "The Session object allows you to persist certain parameters across
        # requests. It also persists cookies across all requests made from the
        # Session instance, and will use urllib3's connection pooling. So if
        # you're making several requests to the same host, the underlying TCP
        # connection will be reused, which can result in a significant
        # performance increase (see HTTP persistent connection)."
        #
        # NOTE: We use a separate requests.Session per scheme+hostname
        # combination, in order to reuse connections to the same hostname to
        # improve efficiency, but avoiding sharing state between different
        # hosts-scheme combinations to minimize subtle security issues.
        # Some cookies may not be HTTP-safe.
        self._sessions: Dict[Tuple[str, str], requests.Session] = {}

        # Default settings
        self.socket_timeout: int = socket_timeout  # seconds
        self.chunk_size: int = chunk_size  # bytes
        self.app_user_agent = app_user_agent

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

        # Get the requests.Response object for this URL.
        #
        # Defer downloading the response body with stream=True.
        # Always set the timeout. This timeout value is interpreted by
        # requests as:
        #  - connect timeout (max delay before first byte is received)
        #  - read (gap) timeout (max delay between bytes received)
        try:
            response = session.get(
                url, stream=True, timeout=self.socket_timeout
            )
        except requests.exceptions.Timeout as e:
            raise exceptions.SlowRetrievalError from e

        # Check response status.
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            response.close()
            status = e.response.status_code
            raise exceptions.DownloadHTTPError(str(e), status) from e

        return self._chunks(response)

    def _chunks(self, response: "requests.Response") -> Iterator[bytes]:
        """A generator function to be returned by fetch.

        This way the caller of fetch can differentiate between connection
        and actual data download.
        """

        try:
            yield from response.iter_content(self.chunk_size)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ) as e:
            raise exceptions.SlowRetrievalError from e

        finally:
            response.close()

    def _get_session(self, url: str) -> requests.Session:
        """Return a different customized requests.Session per schema+hostname
        combination.

        Raises:
            exceptions.DownloadError: When there is a problem parsing the url.
        """
        # Use a different requests.Session per schema+hostname combination, to
        # reuse connections while minimizing subtle security issues.
        parsed_url = parse.urlparse(url)

        if not parsed_url.scheme:
            raise exceptions.DownloadError(f"Failed to parse URL {url}")

        session_index = (parsed_url.scheme, parsed_url.hostname or "")
        session = self._sessions.get(session_index)

        if not session:
            session = requests.Session()
            self._sessions[session_index] = session

            ua = f"python-tuf/{tuf.__version__} {session.headers['User-Agent']}"
            if self.app_user_agent is not None:
                ua = f"{self.app_user_agent} {ua}"
            session.headers["User-Agent"] = ua

            logger.debug("Made new session %s", session_index)
        else:
            logger.debug("Reusing session %s", session_index)

        return session
