# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an interface for network IO abstraction."""

# Imports
import abc
import logging
import tempfile
from contextlib import contextmanager
from typing import IO, Iterator

from tuf.api import exceptions

logger = logging.getLogger(__name__)


# Classes
class FetcherInterface(metaclass=abc.ABCMeta):
    """Defines an interface for abstract network download.

    By providing a concrete implementation of the abstract interface,
    users of the framework can plug-in their preferred/customized
    network stack.

    Implementations of FetcherInterface only need to implement ``_fetch()``.
    The public API of the class is already implemented.
    """

    @abc.abstractmethod
    def _fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS ``url`` from a remote server.

        Implementations must raise ``DownloadHTTPError`` if they receive
        an HTTP error code.

        Implementations may raise any errors but the ones that are not
        ``DownloadErrors`` will be wrapped in a ``DownloadError`` by
        ``fetch()``.

        Args:
            url: URL string that represents a file location.

        Raises:
            exceptions.DownloadHTTPError: HTTP error code was received.

        Returns:
            Bytes iterator
        """
        raise NotImplementedError  # pragma: no cover

    def fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS ``url`` from a remote server.

        Args:
            url: URL string that represents a file location.

        Raises:
            exceptions.DownloadError: An error occurred during download.
            exceptions.DownloadHTTPError: An HTTP error code was received.

        Returns:
            Bytes iterator
        """
        # Ensure that fetch() only raises DownloadErrors, regardless of the
        # fetcher implementation
        try:
            return self._fetch(url)
        except exceptions.DownloadError as e:
            raise e
        except Exception as e:
            raise exceptions.DownloadError(f"Failed to download {url}") from e

    @contextmanager
    def download_file(self, url: str, max_length: int) -> Iterator[IO]:
        """Download file from given ``url``.

        It is recommended to use ``download_file()`` within a ``with``
        block to guarantee that allocated file resources will always
        be released even if download fails.

        Args:
            url: URL string that represents the location of the file.
            max_length: Upper bound of file size in bytes.

        Raises:
            exceptions.DownloadError: An error occurred during download.
            exceptions.DownloadLengthMismatchError: Downloaded bytes exceed
                ``max_length``.
            exceptions.DownloadHTTPError: An HTTP error code was received.

        Yields:
            ``TemporaryFile`` object that points to the contents of ``url``.
        """
        logger.debug("Downloading: %s", url)

        number_of_bytes_received = 0

        with tempfile.TemporaryFile() as temp_file:
            chunks = self.fetch(url)
            for chunk in chunks:
                number_of_bytes_received += len(chunk)
                if number_of_bytes_received > max_length:
                    raise exceptions.DownloadLengthMismatchError(
                        f"Downloaded {number_of_bytes_received} bytes exceeding"
                        f" the maximum allowed length of {max_length}"
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
        """Download bytes from given ``url``.

        Returns the downloaded bytes, otherwise like ``download_file()``.

        Args:
            url: URL string that represents the location of the file.
            max_length: Upper bound of data size in bytes.

        Raises:
            exceptions.DownloadError: An error occurred during download.
            exceptions.DownloadLengthMismatchError: Downloaded bytes exceed
                ``max_length``.
            exceptions.DownloadHTTPError: An HTTP error code was received.

        Returns:
            Content of the file in bytes.
        """
        with self.download_file(url, max_length) as dl_file:
            return dl_file.read()
