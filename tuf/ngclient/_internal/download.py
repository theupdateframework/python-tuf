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
import timeit
from urllib import parse

from securesystemslib import formats as sslib_formats

import tuf
from tuf import exceptions, formats

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)


def download_file(url, required_length, fetcher, strict_required_length=True):
    """
    <Purpose>
      Given the url and length of the desired file, this function opens a
      connection to 'url' and downloads the file while ensuring its length
      matches 'required_length' if 'STRICT_REQUIRED_LENGH' is True (If False,
      the file's length is not checked and a slow retrieval exception is raised
      if the downloaded rate falls below the acceptable rate).

    <Arguments>
      url:
        A URL string that represents the location of the file.

      required_length:
        An integer value representing the length of the file.

      strict_required_length:
        A Boolean indicator used to signal whether we should perform strict
        checking of required_length. True by default. We explicitly set this to
        False when we know that we want to turn this off for downloading the
        timestamp metadata, which has no signed required_length.

    <Side Effects>
      A file object is created on disk to store the contents of 'url'.

    <Exceptions>
      exceptions.DownloadLengthMismatchError, if there was a
      mismatch of observed vs expected lengths while downloading the file.

      securesystemslib.exceptions.FormatError, if any of the arguments are
      improperly formatted.

      Any other unforeseen runtime exception.

    <Returns>
      A file object that points to the contents of 'url'.
    """
    # Do all of the arguments have the appropriate format?
    # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
    sslib_formats.URL_SCHEMA.check_match(url)
    formats.LENGTH_SCHEMA.check_match(required_length)

    # 'url.replace('\\', '/')' is needed for compatibility with Windows-based
    # systems, because they might use back-slashes in place of forward-slashes.
    # This converts it to the common format.  unquote() replaces %xx escapes in
    # a url with their single-character equivalent.  A back-slash may be
    # encoded as %5c in the url, which should also be replaced with a forward
    # slash.
    url = parse.unquote(url).replace("\\", "/")
    logger.info("Downloading: %s", url)

    # This is the temporary file that we will return to contain the contents of
    # the downloaded file.
    temp_file = tempfile.TemporaryFile()  # pylint: disable=consider-using-with

    average_download_speed = 0
    number_of_bytes_received = 0

    try:
        chunks = fetcher.fetch(url, required_length)
        start_time = timeit.default_timer()
        for chunk in chunks:

            stop_time = timeit.default_timer()
            temp_file.write(chunk)

            # Measure the average download speed.
            number_of_bytes_received += len(chunk)
            seconds_spent_receiving = stop_time - start_time
            average_download_speed = (
                number_of_bytes_received / seconds_spent_receiving
            )

            if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
                logger.debug(
                    "The average download speed dropped below the minimum"
                    " average download speed set in tuf.settings.py."
                    " Stopping the download!"
                )
                break

            logger.debug(
                "The average download speed has not dipped below the"
                " minimum average download speed set in tuf.settings.py."
            )

        # Does the total number of downloaded bytes match the required length?
        _check_downloaded_length(
            number_of_bytes_received,
            required_length,
            strict_required_length=strict_required_length,
            average_download_speed=average_download_speed,
        )

    except Exception:
        # Close 'temp_file'.  Any written data is lost.
        temp_file.close()
        logger.debug("Could not download URL: %s", url)
        raise

    else:
        temp_file.seek(0)
        return temp_file


def download_bytes(url, required_length, fetcher, strict_required_length=True):
    """Download bytes from given url

    Returns the downloaded bytes, otherwise like download_file()
    """
    with download_file(
        url, required_length, fetcher, strict_required_length
    ) as dl_file:
        return dl_file.read()


def _check_downloaded_length(
    total_downloaded,
    required_length,
    strict_required_length=True,
    average_download_speed=None,
):
    """
    <Purpose>
      A helper function which checks whether the total number of downloaded
      bytes matches our expectation.

    <Arguments>
      total_downloaded:
        The total number of bytes supposedly downloaded for the file in
        question.

      required_length:
        The total number of bytes expected of the file as seen from its metadata
        The Timestamp role is always downloaded without a known file length, and
        the Root role when the client cannot download any of the required
        top-level roles.  In both cases, 'required_length' is actually an upper
        limit on the length of the downloaded file.

      strict_required_length:
        A Boolean indicator used to signal whether we should perform strict
        checking of required_length. True by default. We explicitly set this to
        False when we know that we want to turn this off for downloading the
        timestamp metadata, which has no signed required_length.

      average_download_speed:
       The average download speed for the downloaded file.

    <Side Effects>
      None.

    <Exceptions>
      securesystemslib.exceptions.DownloadLengthMismatchError, if
      strict_required_length is True and total_downloaded is not equal
      required_length.

      exceptions.SlowRetrievalError, if the total downloaded was
      done in less than the acceptable download speed (as set in
      tuf.settings.py).

    <Returns>
      None.
    """

    if total_downloaded == required_length:
        logger.info("Downloaded %d bytes as expected.", total_downloaded)

    else:
        # What we downloaded is not equal to the required length, but did we ask
        # for strict checking of required length?
        if strict_required_length:
            logger.info(
                "Downloaded %d bytes, but expected %d bytes",
                total_downloaded,
                required_length,
            )

            # If the average download speed is below a certain threshold, we
            # flag this as a possible slow-retrieval attack.
            if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
                raise exceptions.SlowRetrievalError(average_download_speed)

            raise exceptions.DownloadLengthMismatchError(
                required_length, total_downloaded
            )

        # We specifically disabled strict checking of required length, but
        # we will log a warning anyway. This is useful when we wish to
        # download the Timestamp or Root metadata, for which we have no
        # signed metadata; so, we must guess a reasonable required_length
        # for it.
        if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
            raise exceptions.SlowRetrievalError(average_download_speed)

        logger.debug(
            "Good average download speed: %f bytes per second",
            average_download_speed,
        )

        logger.info(
            "Downloaded %d bytes out of upper limit of %d bytes.",
            total_downloaded,
            required_length,
        )
