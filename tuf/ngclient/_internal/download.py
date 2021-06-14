#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  download.py

<Started>
  February 21, 2012.  Based on previous version by Geremy Condra.

<Author>
  Konstantin Andrianov
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Download metadata and target files and check their validity.  The hash and
  length of a downloaded file has to match the hash and length supplied by the
  metadata of that file.
"""
import logging
import tempfile
from contextlib import contextmanager
from urllib import parse

from tuf import exceptions

logger = logging.getLogger(__name__)

@contextmanager
def download_file(url, required_length, fetcher):
    """
    <Purpose>
      Given the url and length of the desired file, this function opens a
      connection to 'url' and downloads the file up to 'required_length'.

    <Arguments>
      url:
        A URL string that represents the location of the file.

      required_length:
        An integer value representing the length of the file or an
        upper boundary.

    <Side Effects>
      A file object is created on disk to store the contents of 'url'.

    <Exceptions>
      exceptions.DownloadLengthMismatchError, if there was a
      mismatch of observed vs expected lengths while downloading the file.

      Any other unforeseen runtime exception.

    <Returns>
      A file object that points to the contents of 'url'.
    """
    # 'url.replace('\\', '/')' is needed for compatibility with Windows-based
    # systems, because they might use back-slashes in place of forward-slashes.
    # This converts it to the common format.  unquote() replaces %xx escapes in
    # a url with their single-character equivalent.  A back-slash may be
    # encoded as %5c in the url, which should also be replaced with a forward
    # slash.
    url = parse.unquote(url).replace("\\", "/")
    logger.debug("Downloading: %s", url)

    number_of_bytes_received = 0

    with tempfile.TemporaryFile() as temp_file:
        chunks = fetcher.fetch(url, required_length)
        for chunk in chunks:
            temp_file.write(chunk)
            number_of_bytes_received += len(chunk)
        if number_of_bytes_received > required_length:
            raise exceptions.DownloadLengthMismatchError(
                required_length, number_of_bytes_received
            )
        temp_file.seek(0)
        yield temp_file


def download_bytes(url, required_length, fetcher):
    """Download bytes from given url

    Returns the downloaded bytes, otherwise like download_file()
    """
    with download_file(url, required_length, fetcher) as dl_file:
        return dl_file.read()
