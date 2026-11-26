# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an interface for network IO abstraction."""

# Imports
import abc
import logging
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import IO

from tuf.api import exceptions

logger = logging.getLogger(__name__)


class _DownloadIterator(Iterator[bytes]):
    """Normalize stream errors and forward explicit close calls."""

    def __init__(self, chunks: Iterator[bytes], url: str) -> None:
        self._chunks = chunks
        self._url = url

    def __next__(self) -> bytes:
        try:
            return next(self._chunks)
        except (StopIteration, exceptions.DownloadError):
            raise
        except Exception as e:
            raise exceptions.DownloadError(
                f"Failed to download {self._url}"
            ) from e

    def close(self) -> None:
        close = getattr(self._chunks, "close", None)
        if close is not None:
            close()


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
        ``fetch()``, including errors raised while iterating over the chunks.

        Args:
            url: URL string that represents a file location.

        Raises:
            DownloadHTTPError: HTTP error code was received.

        Returns:
            Bytes iterator
        """
        raise NotImplementedError  # pragma: no cover

    def fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS ``url`` from a remote server.

        Args:
            url: URL string that represents a file location.

        Raises:
            DownloadError: An error occurred during download.
            DownloadHTTPError: An HTTP error code was received.

        Returns:
            Bytes iterator
        """
        # Start the download now so connection and HTTP errors stay immediate.
        try:
            chunks = self._fetch(url)
        except exceptions.DownloadError:
            raise
        except Exception as e:
            raise exceptions.DownloadError(f"Failed to download {url}") from e

        return _DownloadIterator(chunks, url)

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
            DownloadError: An error occurred during download.
            DownloadLengthMismatchError: Downloaded bytes exceed
                ``max_length``.
            DownloadHTTPError: An HTTP error code was received.

        Yields:
            ``TemporaryFile`` object that points to the contents of ``url``.
        """
        logger.debug("Downloading: %s", url)

        number_of_bytes_received = 0

        with tempfile.TemporaryFile() as temp_file:
            chunks = self.fetch(url)
            try:
                for chunk in chunks:
                    number_of_bytes_received += len(chunk)
                    if number_of_bytes_received > max_length:
                        raise exceptions.DownloadLengthMismatchError(
                            f"Downloaded {number_of_bytes_received} bytes "
                            "exceeding the maximum allowed length of "
                            f"{max_length}"
                        )

                    temp_file.write(chunk)
            except BaseException:
                # Preserve the original error if closing the stream fails.
                with suppress(Exception):
                    close = getattr(chunks, "close", None)
                    if close is not None:
                        close()
                raise

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
            DownloadError: An error occurred during download.
            DownloadLengthMismatchError: Downloaded bytes exceed
                ``max_length``.
            DownloadHTTPError: An HTTP error code was received.

        Returns:
            Content of the file in bytes.
        """
        with self.download_file(url, max_length) as dl_file:
            return dl_file.read()
