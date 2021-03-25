# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an interface for network IO abstraction.
"""

# Imports
import abc

# Classes
class FetcherInterface():
  """Defines an interface for abstract network download.

  By providing a concrete implementation of the abstract interface,
  users of the framework can plug-in their preferred/customized
  network stack.
  """

  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def fetch(self, url, required_length):
    """Fetches the contents of HTTP/HTTPS url from a remote server.

    Ensures the length of the downloaded data is up to 'required_length'.

    Arguments:
      url: A URL string that represents a file location.
      required_length: An integer value representing the file length in bytes.

    Raises:
      tuf.exceptions.SlowRetrievalError: A timeout occurs while receiving data.
      tuf.exceptions.FetcherHTTPError: An HTTP error code is received.

    Returns:
      A bytes iterator
    """
    raise NotImplementedError # pragma: no cover
