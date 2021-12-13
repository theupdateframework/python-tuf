# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Define TUF exceptions used inside the new modern implementation.
The names chosen for TUF Exception classes should end in 'Error' except where
there is a good reason not to, and provide that reason in those cases.
"""


#### General errors ####


class UnsupportedAlgorithmError(Exception):
    """An error while trying to identify a user-specified algorithm."""


class LengthOrHashMismatchError(Exception):
    """An error while checking the length and hash values of an object."""


class FetcherHTTPError(Exception):
    """
    Returned by FetcherInterface implementations for HTTP errors.

    Args:
        message: The HTTP error messsage
        status_code: The HTTP status code
    """

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class URLParsingError(Exception):
    """If we are unable to parse a URL -- for example, if a hostname element
    cannot be isoalted."""


#### Repository errors ####


class RepositoryError(Exception):
    """An error with a repository's state, such as a missing file."""


class UnsignedMetadataError(RepositoryError):
    """An error about metadata object with insufficient threshold of
    signatures."""


class BadVersionNumberError(RepositoryError):
    """An error for metadata that contains an invalid version number."""


class ExpiredMetadataError(RepositoryError):
    """Indicate that a TUF Metadata file has expired."""


class ReplayedMetadataError(RepositoryError):
    """Indicate that some metadata has been replayed to the client.

    Args:
        metadata_role: Name of the role that has been replayed
        downloaded_version: The replayed downloaded version of the metadata
        current_version: The current locally available version.
    """

    def __init__(
        self, metadata_role: str, downloaded_version: int, current_version: int
    ) -> None:
        super().__init__()

        self.metadata_role = metadata_role
        self.downloaded_version = downloaded_version
        self.current_version = current_version

    def __str__(self) -> str:
        return (
            f"Downloaded {self.metadata_role} is older ("
            f"{self.downloaded_version}) than the version currently installed"
            f"({self.current_version})"
        )


#### Download Errors ####


class DownloadError(Exception):
    """An error occurred while attempting to download a file."""


class DownloadLengthMismatchError(DownloadError):
    """Indicate that a mismatch of lengths was seen while downloading a file."""


class SlowRetrievalError(DownloadError):
    """Indicate that downloading a file took an unreasonably long time."""
