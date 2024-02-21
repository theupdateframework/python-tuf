# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Define TUF exceptions used inside the new modern implementation.
The names chosen for TUF Exception classes should end in 'Error' except where
there is a good reason not to, and provide that reason in those cases.
"""


#### Repository errors ####

from securesystemslib.exceptions import StorageError  # noqa: F401


class RepositoryError(Exception):
    """An error with a repository's state, such as a missing file.

    It covers all exceptions that come from the repository side when
    looking from the perspective of users of metadata API or ngclient.
    """


class UnsignedMetadataError(RepositoryError):
    """An error about metadata object with insufficient threshold of
    signatures.
    """


class BadVersionNumberError(RepositoryError):
    """An error for metadata that contains an invalid version number."""


class EqualVersionNumberError(BadVersionNumberError):
    """An error for metadata containing a previously verified version number."""


class ExpiredMetadataError(RepositoryError):
    """Indicate that a TUF Metadata file has expired."""


class LengthOrHashMismatchError(RepositoryError):
    """An error while checking the length and hash values of an object."""


#### Download Errors ####


class DownloadError(Exception):
    """An error occurred while attempting to download a file."""


class DownloadLengthMismatchError(DownloadError):
    """Indicate that a mismatch of lengths was seen while downloading a file."""


class SlowRetrievalError(DownloadError):
    """Indicate that downloading a file took an unreasonably long time."""


class DownloadHTTPError(DownloadError):
    """
    Returned by FetcherInterface implementations for HTTP errors.

    Args:
        message: The HTTP error messsage
        status_code: The HTTP status code
    """

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code
