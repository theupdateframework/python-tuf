# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an interface for network IO abstraction.
"""

# Imports
import abc
import logging
import tempfile
from contextlib import contextmanager
from typing import IO, Iterator
from urllib import parse

from tuf import exceptions

logger = logging.getLogger(__name__)


# Classes
class FetcherInterface:
    """Defines an interface for abstract network download.

    By providing a concrete implementation of the abstract interface,
    users of the framework can plug-in their preferred/customized
    network stack.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def fetch(self, url: str) -> Iterator[bytes]:
        """Fetches the contents of HTTP/HTTPS url from a remote server.

        Arguments:
            url: A URL string that represents a file location.

        Raises:
            tuf.exceptions.SlowRetrievalError: A timeout occurs while receiving
                data.
            tuf.exceptions.FetcherHTTPError: An HTTP error code is received.

        Returns:
            A bytes iterator
        """
        raise NotImplementedError  # pragma: no cover

    @contextmanager
    def download_file(self, url: str, max_length: int) -> Iterator[IO]:
        """Opens a connection to 'url' and downloads the content
        up to 'max_length'.

        Args:
          url: a URL string that represents the location of the file.
          max_length: an integer value representing the length of
              the file or an upper bound.

        Raises:
          DownloadLengthMismatchError: downloaded bytes exceed 'max_length'.

        Yields:
          A TemporaryFile object that points to the contents of 'url'.
        """
        # 'url.replace('\\', '/')' is needed for compatibility with
        # Windows-based systems, because they might use back-slashes in place
        # of forward-slashes. This converts it to the common format.
        # unquote() replaces %xx escapes in a url with their single-character
        # equivalent. A back-slash may beencoded as %5c in the url, which
        # should also be replaced with a forward slash.
        url = parse.unquote(url).replace("\\", "/")
        logger.debug("Downloading: %s", url)

        number_of_bytes_received = 0

        with tempfile.TemporaryFile() as temp_file:
            chunks = self.fetch(url)
            for chunk in chunks:
                number_of_bytes_received += len(chunk)
                if number_of_bytes_received > max_length:
                    raise exceptions.DownloadLengthMismatchError(
                        max_length, number_of_bytes_received
                    )

                temp_file.write(chunk)

            logger.debug(
                "Downloaded %d out of %d bytes",
                number_of_bytes_received,
                max_length,
            )

            temp_file.seek(0)
            yield temp_file

    def download_bytes(self, url: str, max_length: int) -> bytes:
        """Download bytes from given url

        Returns the downloaded bytes, otherwise like download_file()
        """
        with self.download_file(url, max_length) as dl_file:
            return dl_file.read()
