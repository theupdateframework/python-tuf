#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit test for RequestsFetcher.
"""

import io
import logging
import math
import os
import sys
import tempfile
import unittest
from typing import Any, ClassVar, Iterator
from unittest.mock import Mock, patch

import requests
import urllib3.exceptions

from tests import utils
from tuf import exceptions, unittest_toolbox
from tuf.ngclient._internal.requests_fetcher import RequestsFetcher

logger = logging.getLogger(__name__)


class TestFetcher(unittest_toolbox.Modified_TestCase):
    """Test RequestsFetcher class."""

    server_process_handler: ClassVar[utils.TestServerProcess]

    @classmethod
    def setUpClass(cls) -> None:
        # Launch a SimpleHTTPServer (serves files in the current dir).
        cls.server_process_handler = utils.TestServerProcess(log=logger)

    @classmethod
    def tearDownClass(cls) -> None:
        # Stop server process and perform clean up.
        cls.server_process_handler.clean()

    def setUp(self) -> None:
        """
        Create a temporary file and launch a simple server in the
        current working directory.
        """

        unittest_toolbox.Modified_TestCase.setUp(self)

        # Making a temporary data file.
        current_dir = os.getcwd()
        target_filepath = self.make_temp_data_file(directory=current_dir)

        with open(target_filepath, "r", encoding="utf8") as target_fileobj:
            self.file_contents = target_fileobj.read()
            self.file_length = len(self.file_contents)

        self.rel_target_filepath = os.path.basename(target_filepath)
        self.url_prefix = (
            f"http://{utils.TEST_HOST_ADDRESS}:"
            f"{str(self.server_process_handler.port)}"
        )
        self.url = f"{self.url_prefix}/{self.rel_target_filepath}"

        # Instantiate a concrete instance of FetcherInterface
        self.fetcher = RequestsFetcher()

    def tearDown(self) -> None:
        # Remove temporary directory
        unittest_toolbox.Modified_TestCase.tearDown(self)

    # Simple fetch.
    def test_fetch(self) -> None:
        with tempfile.TemporaryFile() as temp_file:
            for chunk in self.fetcher.fetch(self.url):
                temp_file.write(chunk)

            temp_file.seek(0)
            self.assertEqual(
                self.file_contents, temp_file.read().decode("utf-8")
            )

    # URL data downloaded in more than one chunk
    def test_fetch_in_chunks(self) -> None:
        # Set a smaller chunk size to ensure that the file will be downloaded
        # in more than one chunk
        self.fetcher.chunk_size = 4

        # expected_chunks_count: 3
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
            self.assertEqual(
                self.file_contents, temp_file.read().decode("utf-8")
            )
            # Check that we calculate chunks as expected
            self.assertEqual(chunks_count, expected_chunks_count)

    # Incorrect URL parsing
    def test_url_parsing(self) -> None:
        with self.assertRaises(exceptions.URLParsingError):
            self.fetcher.fetch(self.random_string())

    # File not found error
    def test_http_error(self) -> None:
        with self.assertRaises(exceptions.FetcherHTTPError) as cm:
            self.url = f"{self.url_prefix}/non-existing-path"
            self.fetcher.fetch(self.url)
        self.assertEqual(cm.exception.status_code, 404)

    # Response read timeout error
    @patch.object(requests.Session, "get")
    def test_response_read_timeout(self, mock_session_get: Any) -> None:
        mock_response = Mock()
        attr = {
            "raw.read.side_effect": urllib3.exceptions.ReadTimeoutError(
                None, None, "Read timed out."
            )
        }
        mock_response.configure_mock(**attr)
        mock_session_get.return_value = mock_response

        with self.assertRaises(exceptions.SlowRetrievalError):
            next(self.fetcher.fetch(self.url))
        mock_response.raw.read.assert_called_once()

    # Read/connect session timeout error
    @patch.object(
        requests.Session, "get", side_effect=urllib3.exceptions.TimeoutError
    )
    def test_session_get_timeout(self, mock_session_get: Any) -> None:
        with self.assertRaises(exceptions.SlowRetrievalError):
            self.fetcher.fetch(self.url)
        mock_session_get.assert_called_once()

    # Simple bytes download
    def test_download_bytes(self) -> None:
        data = self.fetcher.download_bytes(self.url, self.file_length)
        self.assertEqual(self.file_contents, data.decode("utf-8"))

    # Download file smaller than required max_length
    def test_download_bytes_upper_length(self) -> None:
        data = self.fetcher.download_bytes(self.url, self.file_length + 4)
        self.assertEqual(self.file_contents, data.decode("utf-8"))

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
