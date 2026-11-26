# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit test for Urllib3Fetcher."""

import io
import logging
import math
import os
import sys
import tempfile
import unittest
from collections.abc import Generator, Iterator
from typing import ClassVar
from unittest.mock import MagicMock, Mock, call, patch

import urllib3

from tests import utils
from tuf.api import exceptions
from tuf.ngclient import Urllib3Fetcher
from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)


class TestFetcherInterface(unittest.TestCase):
    def test_custom_fetcher_stream_error(self) -> None:
        stream_error = OSError("stream interrupted")

        class CustomFetcher(FetcherInterface):
            def _fetch(self, url: str) -> Iterator[bytes]:
                yield url.encode()
                raise stream_error

        url = "https://example.com/file"
        chunks = CustomFetcher().fetch(url)
        self.assertEqual(next(chunks), url.encode())
        with self.assertRaises(exceptions.DownloadError) as cm:
            next(chunks)
        self.assertIs(cm.exception.__cause__, stream_error)

    @patch.object(Urllib3Fetcher, "_fetch")
    def test_close_before_iteration(self, fetch: Mock) -> None:
        stream = MagicMock(spec=Generator)
        fetch.return_value = stream

        url = "https://example.com/file"
        chunks = Urllib3Fetcher().fetch(url)
        fetch.assert_called_once_with(url)
        assert hasattr(chunks, "close")
        chunks.close()
        stream.close.assert_called_once_with()
        stream.__next__.assert_not_called()


class TestFetcher(unittest.TestCase):
    """Test Urllib3Fetcher class."""

    server_process_handler: ClassVar[utils.TestServerProcess]

    @classmethod
    def setUpClass(cls) -> None:
        """
        Create a temporary file and launch a simple server in the
        current working directory.
        """
        cls.server_process_handler = utils.TestServerProcess(log=logger)

        cls.file_contents = b"junk data"
        cls.file_length = len(cls.file_contents)
        with tempfile.NamedTemporaryFile(
            dir=os.getcwd(), delete=False
        ) as cls.target_file:
            cls.target_file.write(cls.file_contents)

        cls.url_prefix = (
            f"http://{utils.TEST_HOST_ADDRESS}:"
            f"{cls.server_process_handler.port!s}"
        )
        target_filename = os.path.basename(cls.target_file.name)
        cls.url = f"{cls.url_prefix}/{target_filename}"

    @classmethod
    def tearDownClass(cls) -> None:
        # Stop server process and perform clean up.
        cls.server_process_handler.clean()
        os.remove(cls.target_file.name)

    def setUp(self) -> None:
        # Instantiate a concrete instance of FetcherInterface
        self.fetcher = Urllib3Fetcher()

    def _pooled_response(
        self, data: bytes, headers: dict[str, str] | None = None
    ) -> tuple[urllib3.response.HTTPResponse, Mock]:
        transport = Mock()
        response = urllib3.response.HTTPResponse(
            body=io.BytesIO(data),
            status=200,
            headers=headers,
            preload_content=False,
            pool=transport.pool,
            connection=transport.connection,
        )
        self.addCleanup(response.close)
        return response, transport

    # Simple fetch.
    def test_fetch(self) -> None:
        with tempfile.TemporaryFile() as temp_file:
            for chunk in self.fetcher.fetch(self.url):
                temp_file.write(chunk)

            temp_file.seek(0)
            self.assertEqual(self.file_contents, temp_file.read())

    # URL data downloaded in more than one chunk
    def test_fetch_in_chunks(self) -> None:
        # Set a smaller chunk size to ensure that the file will be downloaded
        # in more than one chunk
        self.fetcher.chunk_size = 4

        # expected_chunks_count: 3 (depends on length of self.file_length)
        expected_chunks_count = math.ceil(
            self.file_length / self.fetcher.chunk_size
        )
        self.assertEqual(expected_chunks_count, 3)

        chunks_count = 0
        with tempfile.TemporaryFile() as temp_file:
            for chunk in self.fetcher.fetch(self.url):
                temp_file.write(chunk)
                chunks_count += 1

            temp_file.seek(0)
            self.assertEqual(self.file_contents, temp_file.read())
            # Check that we calculate chunks as expected
            self.assertEqual(chunks_count, expected_chunks_count)

    # Incorrect URL parsing
    def test_url_parsing(self) -> None:
        with self.assertRaises(exceptions.DownloadError):
            self.fetcher.fetch("http://invalid/")

    # File not found error
    def test_http_error(self) -> None:
        with self.assertRaises(exceptions.DownloadHTTPError) as cm:
            self.url = f"{self.url_prefix}/non-existing-path"
            self.fetcher.fetch(self.url)
        self.assertEqual(cm.exception.status_code, 404)

    # Response read timeout error
    @patch.object(urllib3.PoolManager, "request")
    def test_response_read_timeout(self, mock_session_get: Mock) -> None:
        mock_response = Mock()
        mock_response.status = 200
        attr = {
            "stream.side_effect": urllib3.exceptions.MaxRetryError(
                urllib3.connectionpool.ConnectionPool("localhost"),
                "",
                urllib3.exceptions.TimeoutError(),
            )
        }
        mock_response.configure_mock(**attr)
        mock_session_get.return_value = mock_response

        with self.assertRaises(exceptions.SlowRetrievalError):
            next(self.fetcher.fetch(self.url))
        mock_response.stream.assert_called_once()

    # urllib3 raises ReadTimeoutError directly when the gap timeout expires
    # mid-stream: it is a TimeoutError but not a MaxRetryError, so it is not
    # covered by the MaxRetryError case above.
    @patch.object(urllib3.PoolManager, "request")
    def test_response_read_timeout_error(self, mock_session_get: Mock) -> None:
        mock_response = Mock()
        mock_response.status = 200
        attr = {
            "stream.side_effect": urllib3.exceptions.ReadTimeoutError(
                urllib3.connectionpool.ConnectionPool("localhost"),
                "",
                "Read timed out.",
            )
        }
        mock_response.configure_mock(**attr)
        mock_session_get.return_value = mock_response

        with self.assertRaises(exceptions.SlowRetrievalError):
            next(self.fetcher.fetch(self.url))
        mock_response.stream.assert_called_once()

    # The public download_* API documents DownloadError: a mid-stream timeout
    # must not escape as a raw urllib3 error.
    @patch.object(urllib3.PoolManager, "request")
    def test_download_bytes_read_timeout(self, mock_session_get: Mock) -> None:
        mock_response = Mock()
        mock_response.status = 200
        attr = {
            "stream.side_effect": urllib3.exceptions.ReadTimeoutError(
                urllib3.connectionpool.ConnectionPool("localhost"),
                "",
                "Read timed out.",
            )
        }
        mock_response.configure_mock(**attr)
        mock_session_get.return_value = mock_response

        with self.assertRaises(exceptions.SlowRetrievalError):
            self.fetcher.download_bytes(self.url, self.file_length)

    @patch.object(urllib3.PoolManager, "request")
    def test_download_bytes_interrupted_stream(self, request: Mock) -> None:
        stream_error = urllib3.exceptions.ProtocolError("stream interrupted")

        def interrupted_stream() -> Iterator[bytes]:
            yield b"part"
            raise stream_error

        response = request.return_value
        response.status = 200
        response.stream.return_value = interrupted_stream()

        with self.assertRaises(exceptions.DownloadError) as cm:
            self.fetcher.download_bytes(self.url, self.file_length)
        self.assertIs(cm.exception.__cause__, stream_error)
        response.release_conn.assert_called_once_with()

    @patch.object(urllib3.PoolManager, "request")
    def test_close_stream(self, request: Mock) -> None:
        response = request.return_value
        response.status = 200
        response.stream.return_value = iter([b"first", b"second"])

        chunks = self.fetcher.fetch(self.url)
        self.assertEqual(next(chunks), b"first")
        assert hasattr(chunks, "close")
        chunks.close()
        response.close.assert_called_once_with()
        response.release_conn.assert_called_once_with()

    @patch.object(urllib3.PoolManager, "request")
    def test_close_unread_response(self, request: Mock) -> None:
        response, transport = self._pooled_response(b"unread data")
        request.return_value = response

        chunks = self.fetcher.fetch(self.url)
        request.assert_called_once()
        assert hasattr(chunks, "close")
        chunks.close()
        chunks.close()

        self.assertEqual(list(chunks), [])
        self.assertEqual(response.tell(), 0)
        self.assertTrue(response.closed)
        self.assertEqual(
            transport.mock_calls,
            [
                call.connection.close(),
                call.pool._put_conn(transport.connection),
            ],
        )

    @patch.object(urllib3.PoolManager, "request")
    def test_close_response_on_decode_error(self, request: Mock) -> None:
        data = b"uncompressed response content"
        response, transport = self._pooled_response(
            data, {"Content-Encoding": "gzip"}
        )
        request.return_value = response
        self.fetcher.chunk_size = 8

        with self.assertRaises(exceptions.DownloadError) as cm:
            self.fetcher.download_bytes(self.url, len(data))

        self.assertIsInstance(
            cm.exception.__cause__, urllib3.exceptions.DecodeError
        )
        self.assertLess(response.tell(), len(data))
        self.assertTrue(response.closed)
        self.assertEqual(
            transport.mock_calls,
            [
                call.connection.close(),
                call.pool._put_conn(transport.connection),
            ],
        )

    @patch.object(urllib3.PoolManager, "request")
    def test_complete_read_releases_connection(self, request: Mock) -> None:
        data = b"complete response content"
        response, transport = self._pooled_response(data)
        request.return_value = response

        self.assertEqual(self.fetcher.download_bytes(self.url, len(data)), data)
        self.assertEqual(
            transport.mock_calls, [call.pool._put_conn(transport.connection)]
        )

    @patch.object(Urllib3Fetcher, "_fetch")
    @patch("tuf.ngclient.fetcher.tempfile.TemporaryFile")
    def test_download_bytes_local_write_error(
        self, temporary_file: Mock, fetch: Mock
    ) -> None:
        stream = MagicMock(spec=Generator)
        stream.__next__.return_value = b"part"
        stream.close.side_effect = OSError("close failed")
        fetch.return_value = stream
        write_error = OSError("local write failed")
        temporary_file.return_value.__enter__.return_value.write.side_effect = (
            write_error
        )

        with self.assertRaises(OSError) as cm:
            self.fetcher.download_bytes(self.url, self.file_length)
        self.assertIs(cm.exception, write_error)
        stream.close.assert_called_once_with()

    # Read/connect session timeout error
    @patch.object(
        urllib3.PoolManager,
        "request",
        side_effect=urllib3.exceptions.MaxRetryError(
            urllib3.connectionpool.ConnectionPool("localhost"),
            "",
            urllib3.exceptions.TimeoutError(),
        ),
    )
    def test_session_get_timeout(self, mock_session_get: Mock) -> None:
        with self.assertRaises(exceptions.SlowRetrievalError):
            self.fetcher.fetch(self.url)
        mock_session_get.assert_called_once()

    # A non-timeout connection failure (e.g. TLS error) must surface as the
    # original error, not be masked by an UnboundLocalError on "response".
    @patch.object(
        urllib3.PoolManager,
        "request",
        side_effect=urllib3.exceptions.MaxRetryError(
            urllib3.connectionpool.ConnectionPool("localhost"),
            "",
            urllib3.exceptions.SSLError("certificate verify failed"),
        ),
    )
    def test_session_get_ssl_error(self, mock_session_get: Mock) -> None:
        with self.assertRaises(exceptions.DownloadError) as cm:
            self.fetcher.fetch(self.url)
        mock_session_get.assert_called_once()
        self.assertIsInstance(
            cm.exception.__cause__, urllib3.exceptions.MaxRetryError
        )

    # Simple bytes download
    def test_download_bytes(self) -> None:
        data = self.fetcher.download_bytes(self.url, self.file_length)
        self.assertEqual(self.file_contents, data)

    # Download file smaller than required max_length
    def test_download_bytes_upper_length(self) -> None:
        data = self.fetcher.download_bytes(self.url, self.file_length + 4)
        self.assertEqual(self.file_contents, data)

    # Download a file bigger than expected
    def test_download_bytes_length_mismatch(self) -> None:
        with self.assertRaises(exceptions.DownloadLengthMismatchError):
            self.fetcher.download_bytes(self.url, self.file_length - 4)

    # Simple file download
    def test_download_file(self) -> None:
        with self.fetcher.download_file(
            self.url, self.file_length
        ) as temp_file:
            temp_file.seek(0, io.SEEK_END)
            self.assertEqual(self.file_length, temp_file.tell())

    # Download file smaller than required max_length
    def test_download_file_upper_length(self) -> None:
        with self.fetcher.download_file(
            self.url, self.file_length + 4
        ) as temp_file:
            temp_file.seek(0, io.SEEK_END)
            self.assertEqual(self.file_length, temp_file.tell())

    # Download a file bigger than expected
    def test_download_file_length_mismatch(self) -> None:
        with (
            self.assertRaises(exceptions.DownloadLengthMismatchError),
            self.fetcher.download_file(self.url, self.file_length - 4),
        ):
            pass  # we never get here as download_file() raises


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
