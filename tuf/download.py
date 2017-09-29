"""
<Program Name>
  download.py

<Started>
  February 21, 2012.  Based on previous version by Geremy Condra.

<Author>
  Konstantin Andrianov
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Download metadata and target files and check their validity.  The hash and
  length of a downloaded file has to match the hash and length supplied by the
  metadata of that file.  The downloaded file is technically a  file-like
  object that will automatically destroys itself once closed.  Note that the
  file-like object, 'securesystemslib.util.TempFile', is returned by the
  '_download_file()' function.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import socket
import logging
import time
import timeit
import ssl
import time

import tuf

import securesystemslib
import securesystemslib.util
import six

# 'ssl.match_hostname' was added in Python 3.2.  The vendored version is needed
# for Python 2.7.
try:
  from ssl import match_hostname, CertificateError

except ImportError: # pragma: no cover
  from securesystemslib._vendor.ssl_match_hostname import match_hostname, CertificateError

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.download')



def safe_download(url, required_length):
  """
  <Purpose>
    Given the 'url' and 'required_length' of the desired file, open a connection
    to 'url', download it, and return the contents of the file.  Also ensure
    the length of the downloaded file matches 'required_length' exactly.
    tuf.download.unsafe_download() may be called if an upper download limit is
    preferred.

    'securesystemslib.util.TempFile', the file-like object returned, is used
    instead of regular tempfile object because of additional functionality
    provided, such as handling compressed metadata and automatically closing
    files after moving to final destination.

  <Arguments>
    url:
      A URL string that represents the location of the file.  The URI scheme
      component must be one of 'tuf.settings.SUPPORTED_URI_SCHEMES'.

    required_length:
      An integer value representing the length of the file.  This is an exact
      limit.

  <Side Effects>
    A 'securesystemslib.util.TempFile' object is created on disk to store the
    contents of 'url'.

  <Exceptions>
    tuf.ssl_commons.exceptions.DownloadLengthMismatchError, if there was a
    mismatch of observed vs expected lengths while downloading the file.

    securesystemslib.exceptions.FormatError, if any of the arguments are
    improperly formatted.

    Any other unforeseen runtime exception.

  <Returns>
    A 'securesystemslib.util.TempFile' file-like object that points to the
    contents of 'url'.
  """

  # Do all of the arguments have the appropriate format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.URL_SCHEMA.check_match(url)
  securesystemslib.formats.LENGTH_SCHEMA.check_match(required_length)

  # Ensure 'url' specifies one of the URI schemes in
  # 'tuf.settings.SUPPORTED_URI_SCHEMES'.  Be default, ['http', 'https'] is
  # supported.  If the URI scheme of 'url' is empty or "file", files on the
  # local system can be accessed.  Unexpected files may be accessed by
  # compromised metadata (unlikely to happen if targets.json metadata is signed
  # with offline keys).
  parsed_url = six.moves.urllib.parse.urlparse(url)

  if parsed_url.scheme not in tuf.settings.SUPPORTED_URI_SCHEMES:
    message = \
      repr(url) + ' specifies an unsupported URI scheme.  Supported ' + \
      ' URI Schemes: ' + repr(tuf.settings.SUPPORTED_URI_SCHEMES)
    raise securesystemslib.exceptions.FormatError(message)

  return _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True)





def unsafe_download(url, required_length):
  """
  <Purpose>
    Given the 'url' and 'required_length' of the desired file, open a connection
    to 'url', download it, and return the contents of the file.  Also ensure
    the length of the downloaded file is up to 'required_length', and no larger.
    tuf.download.safe_download() may be called if an exact download limit is
    preferred.

    'securesystemslib.util.TempFile', the file-like object returned, is used
    instead of regular tempfile object because of additional functionality
    provided, such as handling compressed metadata and automatically closing
    files after moving to final destination.

  <Arguments>
    url:
      A URL string that represents the location of the file.  The URI scheme
      component must be one of 'tuf.settings.SUPPORTED_URI_SCHEMES'.

    required_length:
      An integer value representing the length of the file.  This is an upper
      limit.

  <Side Effects>
    A 'securesystemslib.util.TempFile' object is created on disk to store the
    contents of 'url'.

  <Exceptions>
    tuf.ssl_commons.exceptions.DownloadLengthMismatchError, if there was a
    mismatch of observed vs expected lengths while downloading the file.

    securesystemslib.exceptions.FormatError, if any of the arguments are
    improperly formatted.

    Any other unforeseen runtime exception.

  <Returns>
    A 'securesystemslib.util.TempFile' file-like object that points to the
    contents of 'url'.
  """

  # Do all of the arguments have the appropriate format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.URL_SCHEMA.check_match(url)
  securesystemslib.formats.LENGTH_SCHEMA.check_match(required_length)

  # Ensure 'url' specifies one of the URI schemes in
  # 'tuf.settings.SUPPORTED_URI_SCHEMES'.  Be default, ['http', 'https'] is
  # supported.  If the URI scheme of 'url' is empty or "file", files on the
  # local system can be accessed.  Unexpected files may be accessed by
  # compromised metadata (unlikely to happen if targets.json metadata is signed
  # with offline keys).
  parsed_url = six.moves.urllib.parse.urlparse(url)

  if parsed_url.scheme not in tuf.settings.SUPPORTED_URI_SCHEMES:
    message = \
      repr(url) + ' specifies an unsupported URI scheme.  Supported ' + \
      ' URI Schemes: ' + repr(tuf.settings.SUPPORTED_URI_SCHEMES)
    raise securesystemslib.exceptions.FormatError(message)

  return _download_file(url, required_length, STRICT_REQUIRED_LENGTH=False)





def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
  """
  <Purpose>
    Given the url and length of the desired file, this function opens a
    connection to 'url' and downloads the file while ensuring its length
    matches 'required_length' if 'STRICT_REQUIRED_LENGH' is True (If False,
    the file's length is not checked and a slow retrieval exception is raised
    if the downloaded rate falls below the acceptable rate).

    securesystemslib.util.TempFile is used instead of regular tempfile object
    because of additional functionality provided by
    'securesystemslib.util.TempFile'.

  <Arguments>
    url:
      A URL string that represents the location of the file.

    required_length:
      An integer value representing the length of the file.

    STRICT_REQUIRED_LENGTH:
      A Boolean indicator used to signal whether we should perform strict
      checking of required_length. True by default. We explicitly set this to
      False when we know that we want to turn this off for downloading the
      timestamp metadata, which has no signed required_length.

  <Side Effects>
    A 'securesystemslib.util.TempFile' object is created on disk to store the
    contents of 'url'.

  <Exceptions>
    tuf.ssl_commons.exceptions.DownloadLengthMismatchError, if there was a
    mismatch of observed vs expected lengths while downloading the file.

    securesystemslib.exceptions.FormatError, if any of the arguments are
    improperly formatted.

    Any other unforeseen runtime exception.

  <Returns>
    A 'securesystemslib.util.TempFile' file-like object that points to the
    contents of 'url'.
  """

  # Do all of the arguments have the appropriate format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.URL_SCHEMA.check_match(url)
  securesystemslib.formats.LENGTH_SCHEMA.check_match(required_length)

  # 'url.replace()' is for compatibility with Windows-based systems because
  # they might put back-slashes in place of forward-slashes.  This converts it
  # to the common format.
  url = url.replace('\\', '/')
  logger.info('Downloading: ' + repr(url))

  # This is the temporary file that we will return to contain the contents of
  # the downloaded file.
  temp_file = securesystemslib.util.TempFile()

  try:
    # Open the connection to the remote file.
    connection = _open_connection(url)

    # We ask the server about how big it thinks this file should be.
    reported_length = _get_content_length(connection)

    # Then, we check whether the required length matches the reported length.
    _check_content_length(reported_length, required_length,
                          STRICT_REQUIRED_LENGTH)

    # Download the contents of the URL, up to the required length, to a
    # temporary file, and get the total number of downloaded bytes.
    total_downloaded, average_download_speed = \
      _download_fixed_amount_of_data(connection, temp_file, required_length)

    # Does the total number of downloaded bytes match the required length?
    _check_downloaded_length(total_downloaded, required_length,
                             STRICT_REQUIRED_LENGTH=STRICT_REQUIRED_LENGTH,
                             average_download_speed=average_download_speed)

  except:
    # Close 'temp_file'.  Any written data is lost.
    temp_file.close_temp_file()
    logger.exception('Could not download URL: ' + repr(url))
    raise

  else:
    return temp_file





def _download_fixed_amount_of_data(connection, temp_file, required_length):
  """
  <Purpose>
    This is a helper function, where the download really happens. While-block
    reads data from connection a fixed chunk of data at a time, or less, until
    'required_length' is reached.

  <Arguments>
    connection:
      The object that the _open_connection returns for communicating with the
      server about the contents of a URL.

    temp_file:
      A temporary file where the contents at the URL specified by the
      'connection' object will be stored.

    required_length:
      The number of bytes that we must download for the file.  This is almost
      always specified by the TUF metadata for the data file in question
      (except in the case of timestamp metadata, in which case we would fix a
      reasonable upper bound).

  <Side Effects>
    Data from the server will be written to 'temp_file'.

  <Exceptions>
    Runtime or network exceptions will be raised without question.

  <Returns>
    A (total_downloaded, average_download_speed) tuple, where
    'total_downloaded' is the total number of bytes downloaded for the desired
    file and the 'average_download_speed' calculated for the download
    attempt.
  """

  # Tolerate servers with a slow start by ignoring their delivery speed for
  # 'tuf.settings.SLOW_START_GRACE_PERIOD' seconds.  Set 'seconds_spent_receiving'
  # to negative SLOW_START_GRACE_PERIOD seconds, and begin checking the average
  # download speed once it is positive.
  grace_period = -tuf.settings.SLOW_START_GRACE_PERIOD

  # Keep track of total bytes downloaded.
  number_of_bytes_received = 0
  average_download_speed = 0

  start_time = timeit.default_timer()

  try:
    while True:
      # We download a fixed chunk of data in every round. This is so that we
      # can defend against slow retrieval attacks. Furthermore, we do not wish
      # to download an extremely large file in one shot.  Before beginning the
      # round, sleep for a short amount of time so that the CPU is not hogged
      # in the while loop.
      time.sleep(0.05)
      data = b''
      read_amount = min(tuf.settings.CHUNK_SIZE,
                        required_length - number_of_bytes_received)

      try:
        data = connection.read(read_amount)

      # Python 3.2 returns 'IOError' if the remote file object has timed out.
      except (socket.error, IOError):
        pass

      number_of_bytes_received = number_of_bytes_received + len(data)

      # Data successfully read from the connection.  Store it.
      temp_file.write(data)

      if number_of_bytes_received == required_length:
        break

      stop_time = timeit.default_timer()
      seconds_spent_receiving = stop_time - start_time

      if (seconds_spent_receiving + grace_period) < 0:
        continue

      # Measure the average download speed.
      average_download_speed = number_of_bytes_received / seconds_spent_receiving

      if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
        logger.debug('The average download speed dropped below the minimum'
          ' average download speed set in tuf.settings.py.')
        break

      else:
        logger.debug('The average download speed has not dipped below the'
          ' mimimum average download speed set in tuf.settings.py.')

      # We might have no more data to read. Check number of bytes downloaded.
      if not data:
        logger.debug('Downloaded ' + repr(number_of_bytes_received) + '/' +
          repr(required_length) + ' bytes.')

        # Finally, we signal that the download is complete.
        break

  except:
    raise

  else:
    # This else block returns and skips closing the connection in the finally
    # block, so close the connection here.
    connection.close()
    return number_of_bytes_received, average_download_speed

  finally:
    # Whatever happens, make sure that we always close the connection.
    connection.close()





def _get_request(url):
  """
  Wraps the URL to retrieve to protects against "creative"
  interpretation of the RFC: http://bugs.python.org/issue8732

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L147
  """

  return six.moves.urllib.request.Request(url, headers={'Accept-encoding': 'identity'})





def _get_opener(scheme=None):
  """
  Build a urllib2 opener based on whether the user now wants SSL.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L178
  """

  if scheme == "https":
    assert os.path.isfile(tuf.settings.ssl_certificates)

    # If we are going over https, use an opener which will provide SSL
    # certificate verification.
    https_handler = VerifiedHTTPSHandler()
    opener = six.moves.urllib.request.build_opener(https_handler)

    # Strip out HTTPHandler to prevent MITM spoof.
    for handler in opener.handlers:
      if isinstance(handler, six.moves.urllib.request.HTTPHandler):
        opener.handlers.remove(handler)

  else:
    # Otherwise, use the default opener.
    opener = six.moves.urllib.request.build_opener()

  return opener





def _open_connection(url):
  """
  <Purpose>
    Helper function that opens a connection to the url. urllib2 supports http,
    ftp, and file. In python (2.6+) where the ssl module is available, urllib2
    also supports https.

    TODO: Determine whether this follows http redirects and decide if we like
    that. For example, would we not want to allow redirection from ssl to
     non-ssl urls?

  <Arguments>
    url:
      URL string (e.g., 'http://...' or 'ftp://...' or 'file://...')

  <Exceptions>
    None.

  <Side Effects>
    Opens a connection to a remote server.

  <Returns>
    File-like object.
  """

  # urllib2.Request produces a Request object that allows for a finer control
  # of the requesting process. Request object allows to add headers or data to
  # the HTTP request. For instance, request method add_header(key, val) can be
  # used to change/spoof 'User-Agent' from default Python-urllib/x.y to
  # 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)' this can be useful if
  # servers do not recognize connections that originates from
  # Python-urllib/x.y.

  parsed_url = six.moves.urllib.parse.urlparse(url)
  opener = _get_opener(scheme=parsed_url.scheme)
  request = _get_request(url)

  return opener.open(request, timeout = tuf.settings.SOCKET_TIMEOUT)





def _get_content_length(connection):
  """
  <Purpose>
    A helper function that gets the purported file length from server.

  <Arguments>
    connection:
      The object that the _open_connection function returns for communicating
      with the server about the contents of a URL.

  <Side Effects>
    No known side effects.

  <Exceptions>
    Runtime exceptions will be suppressed but logged.

  <Returns>
    reported_length:
      The total number of bytes reported by server. If the process fails, we
      return None; otherwise we would return a nonnegative integer.
  """

  try:
    # What is the length of this document according to the HTTP spec?
    reported_length = connection.info().get('Content-Length')

    # Try casting it as a decimal number.
    reported_length = int(reported_length, 10)

    # Make sure that it is a nonnegative integer.
    assert reported_length > -1

  except:
    message = \
      'Could not get content length about ' + str(connection) + ' from server.'
    logger.exception(message)
    reported_length = None

  finally:
    return reported_length





def _check_content_length(reported_length, required_length, strict_length=True):
  """
  <Purpose>
    A helper function that checks whether the length reported by server is
    equal to the length we expected.

  <Arguments>
    reported_length:
      The total number of bytes reported by the server.

    required_length:
      The total number of bytes obtained from (possibly default) metadata.

    strict_length:
      Boolean that indicates whether the required length of the file is an
      exact match, or an upper limit (e.g., downloading a Timestamp file).

  <Side Effects>
    No known side effects.

  <Exceptions>
    No known exceptions.

  <Returns>
    None.
  """

  logger.debug('The server reported a length of '+repr(reported_length)+' bytes.')
  comparison_result = None

  if reported_length < required_length:
    comparison_result = 'less than'

  elif reported_length > required_length:
    comparison_result = 'greater than'

  else:
    comparison_result = 'equal to'

  if strict_length:
    logger.debug('The reported length is ' + comparison_result + ' the'
      ' required length of '+repr(required_length)+' bytes.')

  else:
    logger.debug('The reported length is ' + comparison_result + ' the upper'
      ' limit of ' + repr(required_length) + ' bytes.')





def _check_downloaded_length(total_downloaded, required_length,
                             STRICT_REQUIRED_LENGTH=True,
                             average_download_speed=None):
  """
  <Purpose>
    A helper function which checks whether the total number of downloaded bytes
    matches our expectation.

  <Arguments>
    total_downloaded:
      The total number of bytes supposedly downloaded for the file in question.

    required_length:
      The total number of bytes expected of the file as seen from its metadata.
      The Timestamp role is always downloaded without a known file length, and
      the Root role when the client cannot download any of the required
      top-level roles.  In both cases, 'required_length' is actually an upper
      limit on the length of the downloaded file.

    STRICT_REQUIRED_LENGTH:
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
    STRICT_REQUIRED_LENGTH is True and total_downloaded is not equal
    required_length.

    tuf.exceptions.SlowRetrievalError, if the total downloaded was
    done in in less than the acceptable download speed (as set in
    tuf.settings.py).

  <Returns>
    None.
  """

  if total_downloaded == required_length:
    logger.info('Downloaded ' + str(total_downloaded) + ' bytes out of the'
      ' expected ' + str(required_length) + ' bytes.')

  else:
    difference_in_bytes = abs(total_downloaded - required_length)

    # What we downloaded is not equal to the required length, but did we ask
    # for strict checking of required length?
    if STRICT_REQUIRED_LENGTH:
      logger.error('Downloaded ' + str(total_downloaded) + ' bytes, but'
        ' expected ' + str(required_length) + ' bytes. There is a difference'
        ' of ' + str(difference_in_bytes) + ' bytes.')

      # If the average download speed is below a certain threshold, we flag
      # this as a possible slow-retrieval attack.
      logger.debug('Average download speed: ' + repr(average_download_speed))
      logger.debug('Minimum average download speed: ' + repr(tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED))

      if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
        raise tuf.exceptions.SlowRetrievalError(average_download_speed)

      else:
        logger.debug('Good average download speed: ' +
                     repr(average_download_speed) + ' bytes per second')

      raise securesystemslib.exceptions.DownloadLengthMismatchError(required_length, total_downloaded)

    else:
      # We specifically disabled strict checking of required length, but we
      # will log a warning anyway. This is useful when we wish to download the
      # Timestamp or Root metadata, for which we have no signed metadata; so,
      # we must guess a reasonable required_length for it.
      if average_download_speed < tuf.settings.MIN_AVERAGE_DOWNLOAD_SPEED:
        raise tuf.exceptions.SlowRetrievalError(average_download_speed)

      else:
        logger.debug('Good average download speed: ' +
                     repr(average_download_speed) + ' bytes per second')

      logger.info('Downloaded ' + str(total_downloaded) + ' bytes out of an'
        ' upper limit of ' + str(required_length) + ' bytes.')





class VerifiedHTTPSConnection(six.moves.http_client.HTTPSConnection):
  """
  A connection that wraps connections with ssl certificate verification.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L72
  """

  def connect(self):

    self.connection_kwargs = {}
    self.connection_kwargs.update(timeout = self.timeout)

    # for >= py2.7
    if hasattr(self, 'source_address'):
      self.connection_kwargs.update(source_address = self.source_address)

    sock = socket.create_connection((self.host, self.port), **self.connection_kwargs)

    # for >= py2.7
    if getattr(self, '_tunnel_host', None):
      self.sock = sock
      self._tunnel()

    # set location of certificate authorities
    assert os.path.isfile(tuf.settings.ssl_certificates)
    cert_path = tuf.settings.ssl_certificates

    # TODO: Disallow SSLv2.
    # http://docs.python.org/dev/library/ssl.html#protocol-versions
    # TODO: Select the right ciphers.
    # http://docs.python.org/dev/library/ssl.html#cipher-selection
    self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=cert_path)

    match_hostname(self.sock.getpeercert(), self.host)





class VerifiedHTTPSHandler(six.moves.urllib.request.HTTPSHandler):
  """
  A HTTPSHandler that uses our own VerifiedHTTPSConnection.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L109
  """

  def __init__(self, connection_class = VerifiedHTTPSConnection):
    self.specialized_conn_class = connection_class
    six.moves.urllib.request.HTTPSHandler.__init__(self)

  def https_open(self, req):
    return self.do_open(self.specialized_conn_class, req)
