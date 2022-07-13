#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit test for RequestsFetcher.
"""

from functools import partialmethod
import io
import json
import logging
import math
import os
import sys
import tempfile
import unittest
from typing import Any, ClassVar, Iterator
from unittest.mock import Mock, patch

import requests
from requests.adapters import ReadTimeoutError  # this is a urllib3 exception

from tests import utils
from tuf.api import exceptions
from tuf.ngclient._internal.requests_fetcher import RequestsFetcher

logger = logging.getLogger(__name__)


class TestFetcher(unittest.TestCase):
    """Test RequestsFetcher class."""

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
            f"{str(cls.server_process_handler.port)}"
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
        self.fetcher = RequestsFetcher()

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

    # Fetch data with Content-Encoding gzip (or deflate)
    def test_fetch_content_encoding(self):
        """
        Regression test for issue #2047

        By default, requests/urllib3 will automatically try to decode data
        that is served with a "Content-Encoding: gzip" header (or "deflate").
        As the length of the decoded data typically would be different from
        the expected number of bytes specified in the TUF targets metadata,
        this would give rise to a DownloadLengthMismatchError later on. Thus,
        we need to ensure that a file served with the "Content-Encoding"
        header is *not* decoded by the RequestsFetcher.
        """
        # Serve dummy file with "Content-Encoding: gzip" header
        content_encoding_header = json.dumps({"Content-Encoding": "gzip"})
        headers = {utils.REQUEST_RESPONSE_HEADERS: content_encoding_header}
        get_with_headers = partialmethod(requests.Session.get, headers=headers)
        target = "tuf.ngclient._internal.requests_fetcher.requests.Session.get"
        # The test file content does not represent a real gzip file,
        # so we can expect an error to be raised if requests/urllib3 tries to
        # decode the file (urllib3 uses zlib for this).
        try:
            with tempfile.TemporaryFile() as temp_file:
                with patch(target, get_with_headers):
                    for chunk in self.fetcher.fetch(self.url):
                        temp_file.write(chunk)
                temp_file.seek(0)
                fetched_data = temp_file.read()
        except requests.exceptions.ContentDecodingError as e:
            self.fail(f"fetch() raised unexpected decoding error: {e}")
        # If all is well, decoding has *not* been attempted, and the fetched
        # data matches the original file contents
        self.assertEqual(self.file_contents, fetched_data)

    # Incorrect URL parsing
    def test_url_parsing(self) -> None:
        with self.assertRaises(exceptions.DownloadError):
            self.fetcher.fetch("missing-scheme-and-hostname-in-url")

    # File not found error
    def test_http_error(self) -> None:
        with self.assertRaises(exceptions.DownloadHTTPError) as cm:
            self.url = f"{self.url_prefix}/non-existing-path"
            self.fetcher.fetch(self.url)
        self.assertEqual(cm.exception.status_code, 404)

    # Response read timeout error
    @patch.object(requests.Session, "get")
    def test_response_read_timeout(self, mock_session_get: Any) -> None:
        mock_response = Mock(raw=Mock())
        attr = {
            "read.side_effect": ReadTimeoutError(
                None, None, "Simulated timeout"
            )
        }
        mock_response.raw.configure_mock(**attr)
        mock_session_get.return_value = mock_response

        with self.assertRaises(exceptions.SlowRetrievalError):
            next(self.fetcher.fetch(self.url))
        mock_response.raw.read.assert_called_once()

    # Read/connect session timeout error
    @patch.object(
        requests.Session,
        "get",
        side_effect=requests.exceptions.Timeout("Simulated timeout"),
    )
    def test_session_get_timeout(self, mock_session_get: Any) -> None:
        with self.assertRaises(exceptions.SlowRetrievalError):
            self.fetcher.fetch(self.url)
        mock_session_get.assert_called_once()

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
    def test_download_file_length_mismatch(self) -> Iterator[Any]:
        with self.assertRaises(exceptions.DownloadLengthMismatchError):
            # Force download_file to execute and raise the error since it is a
            # context manager and returns Iterator[IO]
            yield self.fetcher.download_file(self.url, self.file_length - 4)


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
