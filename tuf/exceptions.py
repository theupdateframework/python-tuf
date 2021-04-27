#!/usr/bin/env python

# Copyright 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  exceptions.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  January 10, 2017

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Define TUF Exceptions.
  The names chosen for TUF Exception classes should end in 'Error' except where
  there is a good reason not to, and provide that reason in those cases.
"""

from urllib import parse

import logging
logger = logging.getLogger(__name__)


class Error(Exception):
  """Indicate a generic error."""


class UnsupportedSpecificationError(Error):
  """
  Metadata received claims to conform to a version of the specification that is
  not supported by this client.
  """

class FormatError(Error):
  """Indicate an error while validating an object's format."""


class InvalidMetadataJSONError(FormatError):
  """Indicate that a metadata file is not valid JSON."""

  def __init__(self, exception):
    super(InvalidMetadataJSONError, self).__init__()

    # Store the original exception.
    self.exception = exception

  def __str__(self):
    return repr(self)

  def __repr__(self):
    # Show the original exception.
    return self.__class__.__name__ + ' : wraps error: ' + repr(self.exception)

    # # Directly instance-reproducing:
    # return self.__class__.__name__ + '(' + repr(self.exception) + ')'


class UnsupportedAlgorithmError(Error):
  """Indicate an error while trying to identify a user-specified algorithm."""


class BadHashError(Error):
  """Indicate an error while checking the value of a hash object."""

  def __init__(self, expected_hash, observed_hash):
    super(BadHashError, self).__init__()

    self.expected_hash = expected_hash
    self.observed_hash = observed_hash

  def __str__(self):
    return (
        'Observed hash (' + repr(self.observed_hash) + ') != expected hash (' +
        repr(self.expected_hash) + ')')

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.expected_hash) + ', ' +
    #     repr(self.observed_hash) + ')')


class BadPasswordError(Error):
  """Indicate an error after encountering an invalid password."""


class UnknownKeyError(Error):
  """Indicate an error while verifying key-like objects (e.g., keyids)."""


class RepositoryError(Error):
  """Indicate an error with a repository's state, such as a missing file."""


class BadVersionNumberError(RepositoryError):
  """Indicate an error for metadata that contains an invalid version number."""


class MissingLocalRepositoryError(RepositoryError):
  """Raised when a local repository could not be found."""


class InsufficientKeysError(Error):
  """Indicate that metadata role lacks a threshold of pubic or private keys."""


class ForbiddenTargetError(RepositoryError):
  """Indicate that a role signed for a target that it was not delegated to."""


class ExpiredMetadataError(RepositoryError):
  """Indicate that a TUF Metadata file has expired."""


class ReplayedMetadataError(RepositoryError):
  """Indicate that some metadata has been replayed to the client."""

  def __init__(self, metadata_role, downloaded_version, current_version):
    super(ReplayedMetadataError, self).__init__()

    self.metadata_role = metadata_role
    self.downloaded_version = downloaded_version
    self.current_version = current_version

  def __str__(self):
    return (
        'Downloaded ' + repr(self.metadata_role) + ' is older (' +
        repr(self.downloaded_version) + ') than the version currently '
        'installed (' + repr(self.current_version) + ').')

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)


class CryptoError(Error):
  """Indicate any cryptography-related errors."""


class BadSignatureError(CryptoError):
  """Indicate that some metadata file has a bad signature."""

  def __init__(self, metadata_role_name):
    super(BadSignatureError, self).__init__()

    self.metadata_role_name = metadata_role_name

  def __str__(self):
    return repr(self.metadata_role_name) + ' metadata has a bad signature.'

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.metadata_role_name) + ')')


class UnknownMethodError(CryptoError):
  """Indicate that a user-specified cryptograpthic method is unknown."""


class UnsupportedLibraryError(Error):
  """Indicate that a supported library could not be located or imported."""


class DownloadError(Error):
  """Indicate an error occurred while attempting to download a file."""


class DownloadLengthMismatchError(DownloadError):
  """Indicate that a mismatch of lengths was seen while downloading a file."""

  def __init__(self, expected_length, observed_length):
    super(DownloadLengthMismatchError, self).__init__()

    self.expected_length = expected_length #bytes
    self.observed_length = observed_length #bytes

  def __str__(self):
    return (
        'Observed length (' + repr(self.observed_length) +
        ') < expected length (' + repr(self.expected_length) + ').')

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.expected_length) + ', ' +
    #     self.observed_length + ')')



class SlowRetrievalError(DownloadError):
  """"Indicate that downloading a file took an unreasonably long time."""

  def __init__(self, average_download_speed):
    super(SlowRetrievalError, self).__init__()

    self.__average_download_speed = average_download_speed #bytes/second

  def __str__(self):
    return (
        'Download was too slow. Average speed: ' +
         repr(self.__average_download_speed) + ' bytes per second.')

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.__average_download_speed + ')')


class KeyAlreadyExistsError(Error):
  """Indicate that a key already exists and cannot be added."""


class RoleAlreadyExistsError(Error):
  """Indicate that a role already exists and cannot be added."""


class UnknownRoleError(Error):
  """Indicate an error trying to locate or identify a specified TUF role."""


class UnknownTargetError(Error):
  """Indicate an error trying to locate or identify a specified target."""


class InvalidNameError(Error):
  """Indicate an error while trying to validate any type of named object."""


class UnsignedMetadataError(RepositoryError):
  """Indicate metadata object with insufficient threshold of signatures."""

  def __init__(self, message, signable):
    super(UnsignedMetadataError, self).__init__()

    self.exception_message = message
    self.signable = signable

  def __str__(self):
    return self.exception_message

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.exception_message) + ', ' +
    #     repr(self.signable) + ')')


class NoWorkingMirrorError(Error):
  """
    An updater will throw this exception in case it could not download a
    metadata or target file.
    A dictionary of Exception instances indexed by every mirror URL will also be
    provided.
  """

  def __init__(self, mirror_errors):
    super(NoWorkingMirrorError, self).__init__()

    # Dictionary of URL strings to Exception instances
    self.mirror_errors = mirror_errors

  def __str__(self):
    all_errors = 'No working mirror was found:'

    for mirror_url, mirror_error in self.mirror_errors.items():
      try:
        # http://docs.python.org/2/library/urlparse.html#urlparse.urlparse
        mirror_url_tokens = parse.urlparse(mirror_url)

      except Exception:
        logger.exception('Failed to parse mirror URL: ' + repr(mirror_url))
        mirror_netloc = mirror_url

      else:
        mirror_netloc = mirror_url_tokens.netloc

      all_errors += '\n  ' + repr(mirror_netloc) + ': ' + repr(mirror_error)

    return all_errors

  def __repr__(self):
    return self.__class__.__name__ + ' : ' + str(self)

    # # Directly instance-reproducing:
    # return (
    #     self.__class__.__name__ + '(' + repr(self.mirror_errors) + ')')



class NotFoundError(Error):
  """If a required configuration or resource is not found."""


class URLMatchesNoPatternError(Error):
  """If a URL does not match a user-specified regular expression."""

class URLParsingError(Error):
  """If we are unable to parse a URL -- for example, if a hostname element
  cannot be isoalted."""

class InvalidConfigurationError(Error):
  """If a configuration object does not match the expected format."""

class FetcherHTTPError(Exception):
  """
  Returned by FetcherInterface implementations for HTTP errors.

  Args:
    message (str): The HTTP error messsage
    status_code (int): The HTTP status code
  """
  def __init__(self, message, status_code):
    super(FetcherHTTPError, self).__init__(message)
    self.status_code = status_code
