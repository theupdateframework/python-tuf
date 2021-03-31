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

import os
from typing import BinaryIO, Dict, TextIO

import securesystemslib
import six

import tuf
import tuf.client_rework.download as download
import tuf.formats

# The type of file to be downloaded from a repository.  The
# 'get_list_of_mirrors' function supports these file types.
_SUPPORTED_FILE_TYPES = ["meta", "target"]


class Mirrors:
    def __init__(self, mirrors_dict: Dict):
        tuf.formats.MIRRORDICT_SCHEMA.check_match(mirrors_dict)
        self._config = mirrors_dict

    def _get_list_of_mirrors(self, file_type, file_path):
        """
        <Purpose>
            Get a list of mirror urls from a mirrors dictionary, provided the type
            and the path of the file with respect to the base url.

        <Arguments>
            file_type:
            Type of data needed for download, must correspond to one of the strings
            in the list ['meta', 'target'].  'meta' for metadata file type or
            'target' for target file type.  It should correspond to
            NAME_SCHEMA format.

            file_path:
            A relative path to the file that corresponds to RELPATH_SCHEMA format.
            Ex: 'http://url_prefix/targets_path/file_path'

        <Exceptions>
            securesystemslib.exceptions.Error, on unsupported 'file_type'.

            securesystemslib.exceptions.FormatError, on bad argument.

        <Return>
            List of mirror urls corresponding to the file_type and file_path.  If no
            match is found, empty list is returned.
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
                # confined_target_dirs is optional and can used to confine the client to
                # certain paths on a repository mirror when fetching target files.
                if confined_target_dirs and not file_in_confined_directories(
                    full_filepath, confined_target_dirs
                ):
                    continue

            # urllib.quote(string) replaces special characters in string using the %xx
            # escape.  This is done to avoid parsing issues of the URL on the server
            # side. Do *NOT* pass URLs with Unicode characters without first encoding
            # the URL as UTF-8. We need a long-term solution with #61.
            # http://bugs.python.org/issue1712522
            file_path = six.moves.urllib.parse.quote(file_path)
            url = os.path.join(mirror_info["url_prefix"], path, file_path)

            # The above os.path.join() result as well as input file_path may be
            # invalid on windows (might contain both separator types), see #1077.
            # Make sure the URL doesn't contain backward slashes on Windows.
            list_of_mirrors.append(url.replace("\\", "/"))

        return list_of_mirrors

    def meta_download(
        self, filename: str, upper_length: int, fetcher: "FetcherInterface"
    ) -> TextIO:
        """
        Download metadata file from the list of metadata mirrors
        """
        file_mirrors = self._get_list_of_mirrors("meta", filename)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = download.download_file(
                    file_mirror,
                    upper_length,
                    fetcher,
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

    def target_download(
        self, filename: str, strict_length: int, fetcher: "FetcherInterface"
    ) -> BinaryIO:
        """
        Download target file from the list of target mirrors
        """
        file_mirrors = self._get_list_of_mirrors("target", filename)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = download.download_file(
                    file_mirror, strict_length, fetcher
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
