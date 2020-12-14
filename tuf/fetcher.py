"""
<Program Name>
  fetcher.py

<Author>
  Teodora Sechkova <tsechkova@vmware.com>

<Started>
  December 14, 2020

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provides an interface for network IO abstraction.
"""

import abc


class FetcherInterface():
  """
  <Purpose>
  Defines an interface for abstract network download which can be implemented
  for a variety of network libraries and configurations.
  """
  __metaclass__ = abc.ABCMeta


  @abc.abstractmethod
  def fetch(self, url, required_length):
    """
    <Purpose>
      Fetches the contents of HTTP/HTTPS url from a remote server up to
      required_length and returns a bytes iterator.

    <Arguments>
      url:
        A URL string that represents the location of the file.

      required_length:
        An integer value representing the length of the file in bytes.

    <Exceptions>
      tuf.exceptions.SlowRetrievalError, if a timeout occurs while receiving
      data from a server

    <Returns>
      A bytes iterator
    """
    raise NotImplementedError # pragma: no cover
