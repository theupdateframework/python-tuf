#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit test for RequestsFetcher.
"""

import logging
import os
import io
import sys
import unittest
import tempfile
import math

import tuf
import tuf.exceptions
import tuf.requests_fetcher
import tuf.unittest_toolbox as unittest_toolbox

from tests import utils

logger = logging.getLogger(__name__)


class TestFetcher(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """
    Create a temporary file and launch a simple server in the
    current working directory.
    """

    unittest_toolbox.Modified_TestCase.setUp(self)

    # Making a temporary file.
    current_dir = os.getcwd()
    target_filepath = self.make_temp_data_file(directory=current_dir)
    self.target_fileobj = open(target_filepath, 'r')
    self.file_contents = self.target_fileobj.read()
    self.file_length = len(self.file_contents)

    # Launch a SimpleHTTPServer (serves files in the current dir).
    self.server_process_handler = utils.TestServerProcess(log=logger)

    rel_target_filepath = os.path.basename(target_filepath)
    self.url = 'http://' + utils.TEST_HOST_ADDRESS + ':' \
        + str(self.server_process_handler.port) + '/' + rel_target_filepath

    # Create a temporary file where the target file chunks are written
    # during fetching
    self.temp_file = tempfile.TemporaryFile()
    self.fetcher = tuf.requests_fetcher.RequestsFetcher()


  # Stop server process and perform clean up.
  def tearDown(self):
    # Cleans the resources and flush the logged lines (if any).
    self.server_process_handler.clean()

    self.target_fileobj.close()
    self.temp_file.close()

    # Remove temporary directory
    unittest_toolbox.Modified_TestCase.tearDown(self)


  # Test: Normal case.
  def test_fetch(self):
    for chunk in self.fetcher.fetch(self.url, self.file_length):
        self.temp_file.write(chunk)

    self.temp_file.seek(0)
    temp_file_data = self.temp_file.read().decode('utf-8')
    self.assertEqual(self.file_contents, temp_file_data)

  # Test if fetcher downloads file up to a required length
  def test_fetch_restricted_length(self):
    for chunk in self.fetcher.fetch(self.url, self.file_length-4):
        self.temp_file.write(chunk)

    self.temp_file.seek(0, io.SEEK_END)
    self.assertEqual(self.temp_file.tell(), self.file_length-4)


  # Test that fetcher does not download more than actual file length
  def test_fetch_upper_length(self):
    for chunk in self.fetcher.fetch(self.url, self.file_length+4):
        self.temp_file.write(chunk)

    self.temp_file.seek(0, io.SEEK_END)
    self.assertEqual(self.temp_file.tell(), self.file_length)


  # Test incorrect URL parsing
  def test_url_parsing(self):
    with self.assertRaises(tuf.exceptions.URLParsingError):
      self.fetcher.fetch(self.random_string(), self.file_length)


  # Test: Normal case with url data downloaded in more than one chunk
  def test_fetch_in_chunks(self):
    # Set smaller chunk size to ensure that the file will be downloaded
    # in more than one chunk
    default_chunk_size = tuf.settings.CHUNK_SIZE
    tuf.settings.CHUNK_SIZE = 4

    # expected_chunks_count: 3
    expected_chunks_count = math.ceil(self.file_length/tuf.settings.CHUNK_SIZE)
    self.assertEqual(expected_chunks_count, 3)

    chunks_count = 0
    for chunk in self.fetcher.fetch(self.url, self.file_length):
      self.temp_file.write(chunk)
      chunks_count+=1

    self.temp_file.seek(0)
    temp_file_data = self.temp_file.read().decode('utf-8')
    self.assertEqual(self.file_contents, temp_file_data)
    # Check that we calculate chunks as expected
    self.assertEqual(chunks_count, expected_chunks_count)

    # Restore default settings
    tuf.settings.CHUNK_SIZE = default_chunk_size



# Run unit test.
if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
