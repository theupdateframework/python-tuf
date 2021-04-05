#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  mirrors.py

<Author>
  Konstantin Andrianov.
  Derived from original mirrors.py written by Geremy Condra.

<Started>
  March 12, 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Extract a list of mirror urls corresponding to the file type and the location
  of the file with respect to the base url.
"""


# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import logging
import os
import tempfile
import timeit
from typing import BinaryIO, Dict, Optional, TextIO

import securesystemslib
import six

import tuf
import tuf.formats
from tuf.requests_fetcher import RequestsFetcher

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)

# The type of file to be downloaded from a repository.  The
# 'get_list_of_mirrors' function supports these file types.
_SUPPORTED_FILE_TYPES = ["meta", "target"]


class Mirrors:
    def __init__(
        self, mirrors_dict: Dict, fetcher: Optional["FetcherInterface"] = None
    ):
        tuf.formats.MIRRORDICT_SCHEMA.check_match(mirrors_dict)
        self._config = mirrors_dict

        if fetcher is None:
            self._fetcher = RequestsFetcher()
        else:
            self._fetcher = fetcher

    def _get_list_of_mirrors(self, file_type, file_path):
        """
        <Purpose>
            Get a list of mirror urls from a mirrors dictionary, provided the
                type and the path of the file with respect to the base url.

        <Arguments>
            file_type:
            Type of data needed for download, must correspond to one of the
            strings in the list ['meta', 'target'].  'meta' for metadata file
            type or 'target' for target file type.  It should correspond to
            NAME_SCHEMA format.

            file_path:
            A relative path to the file that corresponds to RELPATH_SCHEMA
            format. Ex: 'http://url_prefix/targets_path/file_path'

        <Exceptions>
            securesystemslib.exceptions.Error, on unsupported 'file_type'.

            securesystemslib.exceptions.FormatError, on bad argument.

        <Return>
            List of mirror urls corresponding to the file_type and file_path.
            If no match is found, empty list is returned.
        """

        # Checking if all the arguments have appropriate format.
        tuf.formats.RELPATH_SCHEMA.check_match(file_path)
        securesystemslib.formats.NAME_SCHEMA.check_match(file_type)

        # Verify 'file_type' is supported.
        if file_type not in _SUPPORTED_FILE_TYPES:
            raise sslib_exceptions.Error(
                "Invalid file_type argument."
                "  Supported file types: " + repr(_SUPPORTED_FILE_TYPES)
            )
        path_key = "metadata_path" if file_type == "meta" else "targets_path"

        list_of_mirrors = []
        for junk, mirror_info in six.iteritems(self._config):
            # Does mirror serve this file type at all?
            path = mirror_info.get(path_key)
            if path is None:
                continue

            # for targets, ensure directory confinement
            if path_key == "targets_path":
                full_filepath = os.path.join(path, file_path)
                confined_target_dirs = mirror_info.get("confined_target_dirs")
                # confined_target_dirs is optional and can used to confine the
                # client to certain paths on a repository mirror when fetching
                # target files.
                if confined_target_dirs and not file_in_confined_directories(
                    full_filepath, confined_target_dirs
                ):
                    continue

            # urllib.quote(string) replaces special characters in string using
            # the %xx escape.  This is done to avoid parsing issues of the URL
            # on the server side. Do *NOT* pass URLs with Unicode characters
            # without first encoding the URL as UTF-8. We need a long-term
            # solution with #61. http://bugs.python.org/issue1712522
            file_path = six.moves.urllib.parse.quote(file_path)
            url = os.path.join(mirror_info["url_prefix"], path, file_path)

            # The above os.path.join() result as well as input file_path may be
            # invalid on windows (might contain both separator types),
            # see #1077.
            # Make sure the URL doesn't contain backward slashes on Windows.
            list_of_mirrors.append(url.replace("\\", "/"))

        return list_of_mirrors

    def meta_download(self, filename: str, upper_length: int) -> TextIO:
        """
        Download metadata file from the list of metadata mirrors
        """
        file_mirrors = self._get_list_of_mirrors("meta", filename)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = self._download_file(
                    file_mirror,
                    upper_length,
                    STRICT_REQUIRED_LENGTH=False,
                )

                temp_obj.seek(0)
                yield temp_obj

            except Exception as exception:
                file_mirror_errors[file_mirror] = exception

            finally:
                if file_mirror_errors:
                    raise tuf.exceptions.NoWorkingMirrorError(
                        file_mirror_errors
                    )

    def target_download(self, filename: str, strict_length: int) -> BinaryIO:
        """
        Download target file from the list of target mirrors
        """
        file_mirrors = self._get_list_of_mirrors("target", filename)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = self._download_file(file_mirror, strict_length)

                temp_obj.seek(0)
                yield temp_obj

            except Exception as exception:
                file_mirror_errors[file_mirror] = exception

            finally:
                if file_mirror_errors:
                    raise tuf.exceptions.NoWorkingMirrorError(
                        file_mirror_errors
                    )

    def _download_file(self, url, required_length, STRICT_REQUIRED_LENGTH=True):
        """
        <Purpose>
        Given the url and length of the desired file, this function opens a
        connection to 'url' and downloads the file while ensuring its length
        matches 'required_length' if 'STRICT_REQUIRED_LENGH' is True (If False,
        the file's length is not checked and a slow retrieval exception is
        raised if the downloaded rate falls below the acceptable rate).

        <Arguments>
        url:
            A URL string that represents the location of the file.

        required_length:
            An integer value representing the length of the file.

        STRICT_REQUIRED_LENGTH:
            A Boolean indicator used to signal whether we should perform strict
            checking of required_length. True by default. We explicitly set this
            to False when we know that we want to turn this off for downloading
            the timestamp metadata, which has no signed required_length.

        <Side Effects>
        A file object is created on disk to store the contents of 'url'.

        <Exceptions>
        tuf.exceptions.DownloadLengthMismatchError, if there was a
        mismatch of observed vs expected lengths while downloading the file.

        securesystemslib.exceptions.FormatError, if any of the arguments are
        improperly formatted.

        Any other unforeseen runtime exception.

        <Returns>
        A file object that points to the contents of 'url'.
        """
        # Do all of the arguments have the appropriate format?
        # Raise 'securesystemslib.exceptions.FormatError' if there is
        # a mismatch.
        securesystemslib.formats.URL_SCHEMA.check_match(url)
        tuf.formats.LENGTH_SCHEMA.check_match(required_length)

        # 'url.replace('\\', '/')' is needed for compatibility with
        # Windows-based systems, because they might use back-slashes in place
        # of forward-slashes. This converts it to the common format.  unquote()
        # replaces %xx escapes in a url with their single-character equivalent.
        # A back-slash may be encoded as %5c in the url, which should also be
        # replaced with a forward slash.
        url = six.moves.urllib.parse.unquote(url).replace("\\", "/")
        msg = f"Downloading: {url}"
        logger.info(msg)

        # This is the temporary file that we will return to contain the
        # contents of the downloaded file.
        temp_file = tempfile.TemporaryFile()

        average_download_speed = 0
        number_of_bytes_received = 0

        try:
            chunks = self._fetcher.fetch(url, required_length)
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

                if (
                    average_download_speed
                    < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED
                ):
                    logger.debug(
                        "The average download speed dropped below the minimum"
                        " average download speed set in tuf.settings.py. "
                        " Stopping the download!"
                    )
                    break

                else:
                    logger.debug(
                        "The average download speed has not dipped below the"
                        " minimum average download speed set"
                        " in tuf.settings.py."
                    )

            # Does the total number of downloaded bytes match the required
            # length?
            self._check_downloaded_length(
                number_of_bytes_received,
                required_length,
                STRICT_REQUIRED_LENGTH=STRICT_REQUIRED_LENGTH,
                average_download_speed=average_download_speed,
            )

        except Exception:
            # Close 'temp_file'.  Any written data is lost.
            temp_file.close()
            msg = f"Could not download URL: {url}"
            logger.debug(msg)
            raise

        else:
            return temp_file

    @staticmethod
    def _check_downloaded_length(
        total_downloaded,
        required_length,
        STRICT_REQUIRED_LENGTH=True,
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
            The total number of bytes expected of the file as seen from its
            metadata. The Timestamp role is always downloaded without a known
            file length, and the Root role when the client cannot download any
            of the required top-level roles.  In both cases, 'required_length'
            is actually an upper limit on the length of the downloaded file.

        STRICT_REQUIRED_LENGTH:
            A Boolean indicator used to signal whether we should perform strict
            checking of required_length. True by default. We explicitly set this
            to False when we know that we want to turn this off for downloading
            the timestamp metadata, which has no signed required_length.

        average_download_speed:
        The average download speed for the downloaded file.

        <Side Effects>
        None.

        <Exceptions>
        securesystemslib.exceptions.DownloadLengthMismatchError, if
        STRICT_REQUIRED_LENGTH is True and total_downloaded is not equal
        required_length.

        tuf.exceptions.SlowRetrievalError, if the total downloaded was
        done in less than the acceptable download speed (as set in
        tuf.settings.py).

        <Returns>
        None.
        """

        if total_downloaded == required_length:
            msg = (
                f"Downloaded {total_downloaded} bytes out of the"
                f" expected {required_length} bytes."
            )
            logger.info(msg)

        else:
            difference_in_bytes = abs(total_downloaded - required_length)

            # What we downloaded is not equal to the required length, but did
            # we ask for strict checking of required length?
            if STRICT_REQUIRED_LENGTH:
                msg = (
                    f"Downloaded {total_downloaded} bytes, but expected"
                    f"{required_length} bytes. There is a difference of"
                    f"{difference_in_bytes} bytes."
                )
                logger.info(msg)

                # If the average download speed is below a certain threshold,
                # we flag this as a possible slow-retrieval attack.
                msg = (
                    f"Average download speed: {average_download_speed}\n"
                    f"Minimum average download speed: "
                    f"{tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED}"
                )
                logger.debug(msg)

                if (
                    average_download_speed
                    < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED
                ):
                    raise tuf.exceptions.SlowRetrievalError(
                        average_download_speed
                    )

                else:
                    msg = (
                        f"Good average download speed: "
                        f"{average_download_speed} bytes per second"
                    )
                    logger.debug(msg)

                raise tuf.exceptions.DownloadLengthMismatchError(
                    required_length, total_downloaded
                )

            else:
                # We specifically disabled strict checking of required length,
                # but we will log a warning anyway. This is useful when we wish
                # to download the Timestamp or Root metadata, for which we have
                # no signed metadata; so, we must guess a reasonable
                # required_length for it.
                if (
                    average_download_speed
                    < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED
                ):
                    raise tuf.exceptions.SlowRetrievalError(
                        average_download_speed
                    )

                else:
                    msg = (
                        f"Good average download speed: "
                        f"{average_download_speed} bytes per second"
                    )
                    logger.debug(msg)

                msg = (
                    f"Downloaded {total_downloaded} bytes out of an "
                    f"upper limit of {required_length} bytes."
                )
                logger.info(msg)
