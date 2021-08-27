#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit test for RequestsFetcher.
"""

import io
import logging
import os
import sys
import unittest
import tempfile
import math

from tests import utils
from tuf import exceptions, unittest_toolbox
from tuf.ngclient._internal.requests_fetcher import RequestsFetcher

logger = logging.getLogger(__name__)


class TestFetcher(unittest_toolbox.Modified_TestCase):

    @classmethod
    def setUpClass(cls):
        # Launch a SimpleHTTPServer (serves files in the current dir).
        cls.server_process_handler = utils.TestServerProcess(log=logger)

    @classmethod
    def tearDownClass(cls):
        # Stop server process and perform clean up.
        cls.server_process_handler.clean()

    def setUp(self):
        """
        Create a temporary file and launch a simple server in the
        current working directory.
        """

        unittest_toolbox.Modified_TestCase.setUp(self)

        # Making a temporary data file.
        current_dir = os.getcwd()
        target_filepath = self.make_temp_data_file(directory=current_dir)

        self.target_fileobj = open(target_filepath, "r")
        self.file_contents = self.target_fileobj.read()
        self.file_length = len(self.file_contents)
        self.rel_target_filepath = os.path.basename(target_filepath)
        self.url = f"http://{utils.TEST_HOST_ADDRESS}:{str(self.server_process_handler.port)}/{self.rel_target_filepath}"

        # Instantiate a concrete instance of FetcherInterface
        self.fetcher = RequestsFetcher()

    def tearDown(self):
        self.target_fileobj.close()
        # Remove temporary directory
        unittest_toolbox.Modified_TestCase.tearDown(self)

    # Simple fetch.
    def test_fetch(self):
        with tempfile.TemporaryFile() as temp_file:
            for chunk in self.fetcher.fetch(self.url):
                temp_file.write(chunk)

            temp_file.seek(0)
            self.assertEqual(
                self.file_contents, temp_file.read().decode("utf-8")
            )

    # URL data downloaded in more than one chunk
    def test_fetch_in_chunks(self):
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
    def test_url_parsing(self):
        with self.assertRaises(exceptions.URLParsingError):
            self.fetcher.fetch(self.random_string())

    # File not found error
    def test_http_error(self):
        with self.assertRaises(exceptions.FetcherHTTPError) as cm:
            self.url = f"http://{utils.TEST_HOST_ADDRESS}:{str(self.server_process_handler.port)}/non-existing-path"
            self.fetcher.fetch(self.url)
        self.assertEqual(cm.exception.status_code, 404)

    # Simple bytes download
    def test_download_bytes(self):
        data = self.fetcher.download_bytes(self.url, self.file_length)
        self.assertEqual(self.file_contents, data.decode("utf-8"))

    # Download file smaller than required max_length
    def test_download_bytes_upper_length(self):
        data = self.fetcher.download_bytes(self.url, self.file_length + 4)
        self.assertEqual(self.file_contents, data.decode("utf-8"))

    # Download a file bigger than expected
    def test_download_bytes_length_mismatch(self):
        with self.assertRaises(exceptions.DownloadLengthMismatchError):
            self.fetcher.download_bytes(self.url, self.file_length - 4)

    # Simple file download
    def test_download_file(self):
        with self.fetcher.download_file(
            self.url, self.file_length
        ) as temp_file:
            temp_file.seek(0, io.SEEK_END)
            self.assertEqual(self.file_length, temp_file.tell())

    # Download file smaller than required max_length
    def test_download_file_upper_length(self):
        with self.fetcher.download_file(
            self.url, self.file_length + 4
        ) as temp_file:
            temp_file.seek(0, io.SEEK_END)
            self.assertEqual(self.file_length, temp_file.tell())

    # Download a file bigger than expected
    def test_download_file_length_mismatch(self):
        with self.assertRaises(exceptions.DownloadLengthMismatchError):
            yield self.fetcher.download_file(self.url, self.file_length - 4)


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
