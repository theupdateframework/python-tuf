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
  Perform any file downloads and check their validity.  This means that the
  hash and length of a downloaded file has to match the hash and length
  supplied by the metadata of that file.  The downloaded file is technically a 
  file-like object that will automatically destroys itself once closed.  Note
  that the file-like object, 'tuf.util.TempFile', is returned by the
  '_download_file()' function.
  
"""

# Induce "true division" (http://www.python.org/dev/peps/pep-0238/).
from __future__ import division

import httplib
import logging
import os.path
import socket
import timeit

import tuf
import tuf.conf
import tuf.hash
import tuf.util
import tuf.formats

from tuf.compatibility import httplib, ssl, urllib2, urlparse

if ssl:
    from tuf.compatibility import match_hostname
else:
    raise tuf.Error("No SSL support!")    # TODO: degrade gracefully

# We will be overriding socket._fileobject to perform non-blocking socket
# reads.  Therefore, we will need these global variables.
# http://hg.python.org/cpython/file/5be3fa83d436/Lib/socket.py#l84

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

try:
  import errno
except ImportError:
  errno = None
EINTR = getattr(errno, 'EINTR', 4)

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.download')





class SaferSocketFileObject(socket._fileobject):
  """We override socket._fileobject to produce a file-like object which reads
  from a socket more safely than its ancestor. One the safety properties is
  that reading from a socket must be a non-blocking operation."""

  def __init__(self, sock, mode='rb', bufsize=-1, close=False):
    super(SaferSocketFileObject, self).__init__(sock, mode=mode,
                                                bufsize=bufsize, close=close)

    # Count the number of bytes received with this socket.
    self.__number_of_bytes_received = 0
    # Count the seconds spent receiving with this socket. Tolerate servers with
    # a slow start by ignoring their delivery speed for
    # tuf.conf.SLOW_START_GRACE_PERIOD seconds.
    assert tuf.conf.SLOW_START_GRACE_PERIOD > 0
    self.__seconds_spent_receiving = -tuf.conf.SLOW_START_GRACE_PERIOD
    # Remember the time a clock was started.
    self.__start_time = None





  def __start_clock(self):
    """
    <Purpose>
      Start the clock to measure time difference later.

    <Arguments>
      None.

    <Exceptions>
      AssertionError:
        When any internal condition is not true.

    <Side Effects>
      Start time is kept inside this object.

    <Returns>
      None.

    """

    # We must have reset the clock before this.
    assert self.__start_time is None
    # We use (platform-specific) wall time, so it will be imprecise sometimes.
    self.__start_time = timeit.default_timer()





  def __stop_clock_and_check_speed(self, data_length):
    """
    <Purpose>
      Stop the clock and try to detect slow retrieval.

    <Arguments>
      data_length:
        A nonnegative integer indicating the size of data retrieved in bytes.

    <Exceptions>
      tuf.SlowRetrievalError:
        When slow retrieval is detected.

      AssertionError:
        When any internal condition is not true.

    <Side Effects>
      Start time is cleared inside this object.

    <Returns>
      None.

    """

    # We use (platform-specific) wall time, so it will be imprecise sometimes.
    stop_time = timeit.default_timer()
    # We must have already started the clock.
    assert self.__start_time > 0
    time_delta = stop_time-self.__start_time
    # Reset the clock.
    self.__start_time = None

    # Measure the average download speed.
    self.__number_of_bytes_received += data_length
    self.__seconds_spent_receiving += time_delta

    if self.__seconds_spent_receiving > 0:
      average_download_speed = \
        self.__number_of_bytes_received/self.__seconds_spent_receiving

      # If the average download speed is below a certain threshold, we flag this
      # as a possible slow-retrieval attack. This threshold will determine our
      # bias: if it is too low, we will have more false positives; if it is too
      # high, we will have more false negatives.
      if average_download_speed < tuf.conf.MIN_AVERAGE_DOWNLOAD_SPEED:
          raise tuf.SlowRetrievalError(average_download_speed)
      else:
        logger.debug('Good average download speed: '+\
                     str(average_download_speed)+' bytes/second')
    else:
      logger.debug('Ignoring average download speed for another: '+\
                   str(-self.__seconds_spent_receiving)+' seconds')






  def read(self, size):
    """
    <Purpose>
      We override the ancestor read (socket._fileobject.read) operation to be a
      non-blocking operation.

      Original code is at:
      http://hg.python.org/cpython/file/5be3fa83d436/Lib/socket.py#l336

    <Arguments>
      size:
        The length of the data chunk that we would like to download. We assume
        that the size of the expected data chunk is accurate; otherwise, we are
        liable to miscount the number of truly slowly-retrieved chunks.

    <Exceptions>
      tuf.SlowRetrievalError, in case we detect a slow-retrieval attack.

      Any other exception thrown by socket._fileobject.read.

    <Side Effects>
      None.

    <Returns>
      Received data up to 'size' bytes.

    """

    # We should never try to specify a negative size.
    assert size >= 0

    # Use max, disallow tiny reads in a loop as they are very inefficient.
    # We never leave read() with any leftover data from a new recv() call
    # in our internal buffer.
    rbufsize = max(self._rbufsize, self.default_bufsize)
    # Our use of StringIO rather than lists of string objects returned by
    # recv() minimizes memory usage and fragmentation that occurs when
    # rbufsize is large compared to the typical return value of recv().
    buf = self._rbuf
    buf.seek(0, 2)  # seek end

    # Read until size bytes or EOF seen, whichever comes first
    buf_len = buf.tell()
    if buf_len >= size:
      # Already have size bytes in our buffer?  Extract and return.
      buf.seek(0)
      rv = buf.read(size)
      self._rbuf = StringIO()
      self._rbuf.write(buf.read())
      return rv

    self._rbuf = StringIO()  # reset _rbuf.  we consume it via buf.
    # Since we try to detect slow retrieval, this should not be an infinite loop.
    while True:
      left = size - buf_len
      # recv() will malloc the amount of memory given as its
      # parameter even though it often returns much less data
      # than that.  The returned data string is short lived
      # as we copy it into a StringIO and free it.  This avoids
      # fragmentation issues on many platforms.
      try:
        self.__start_clock()
        data = self._sock.recv(left)
      except socket.timeout:
        self.__stop_clock_and_check_speed(0)
        continue
      except socket.error, e:
        if e.args[0] == EINTR:
          self.__stop_clock_and_check_speed(0)
          continue
        raise
      else:
        self.__stop_clock_and_check_speed(len(data))
      if not data:
        break
      n = len(data)
      if n == size and not buf_len:
        # Shortcut.  Avoid buffer data copies when:
        # - We have no data in our buffer.
        # AND
        # - Our call to recv returned exactly the
        #   number of bytes we were asked to read.
        return data
      if n == left:
        buf.write(data)
        del data  # explicit free
        break
      assert n <= left, "recv(%d) returned %d bytes" % (left, n)
      buf.write(data)
      buf_len += n
      del data  # explicit free
      #assert buf_len == buf.tell()
    return buf.getvalue()





class SaferHTTPResponse(httplib.HTTPResponse):
  """A safer version of httplib.HTTPResponse, in which we only use safe socket
  file-like objects."""

  def __init__(self, sock, debuglevel=0, strict=0, method=None,
               buffering=False):
    httplib.HTTPResponse.__init__(self, sock, debuglevel=debuglevel,
                                  strict=strict, method=method,
                                  buffering=buffering)

    # Delete the previous socket file-like object...
    del self.fp
    # ...and replace it with our safer version.
    if buffering:
      self.fp = SaferSocketFileObject(sock._sock, 'rb')
    else:
      self.fp = SaferSocketFileObject(sock._sock, 'rb', 0)





class VerifiedHTTPSConnection(httplib.HTTPSConnection):
  """
  A connection that wraps connections with ssl certificate verification.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L72
  """

  def connect(self):

    self.connection_kwargs = {}

    #TODO: refactor compatibility logic into tuf.compatibility?

    # for > py2.5
    if hasattr(self, 'timeout'):
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
    assert os.path.isfile( tuf.conf.ssl_certificates )
    cert_path = tuf.conf.ssl_certificates

    # TODO: Disallow SSLv2.
    # http://docs.python.org/dev/library/ssl.html#protocol-versions
    # TODO: Select the right ciphers.
    # http://docs.python.org/dev/library/ssl.html#cipher-selection
    self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=cert_path)

    match_hostname(self.sock.getpeercert(), self.host)





class VerifiedHTTPSHandler(urllib2.HTTPSHandler):
  """
  A HTTPSHandler that uses our own VerifiedHTTPSConnection.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L109
  """

  def __init__(self, connection_class = VerifiedHTTPSConnection):
    self.specialized_conn_class = connection_class
    urllib2.HTTPSHandler.__init__(self)

  def https_open(self, req):
    return self.do_open(self.specialized_conn_class, req)





def _get_request(url):
  """
  Wraps the URL to retrieve to protects against "creative"
  interpretation of the RFC: http://bugs.python.org/issue8732

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L147
  """

  return urllib2.Request(url, headers={'Accept-encoding': 'identity'})





def _get_opener(scheme=None):
  """
  Build a urllib2 opener based on whether the user now wants SSL.

  https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L178
  """

  if scheme == "https":
    assert os.path.isfile(tuf.conf.ssl_certificates)

    # If we are going over https, use an opener which will provide SSL
    # certificate verification.
    https_handler = VerifiedHTTPSHandler()
    opener = urllib2.build_opener(https_handler)

    # strip out HTTPHandler to prevent MITM spoof
    for handler in opener.handlers:
      if isinstance(handler, urllib2.HTTPHandler):
        opener.handlers.remove(handler)
  else:
    # Otherwise, use the default opener.
    opener = urllib2.build_opener()

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

  parsed_url = urlparse.urlparse(url)
  opener = _get_opener(scheme=parsed_url.scheme)
  request = _get_request(url)
  return opener.open(request)





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
    total_downloaded:
      The total number of bytes we have downloaded for the desired file and
      which should be equal to 'required_length'.

  """

  # Keep track of total bytes downloaded.
  total_downloaded = 0

  try:
    while True:
      # We download a fixed chunk of data in every round. This is so that we
      # can defend against slow retrieval attacks. Furthermore, we do not wish
      # to download an extremely large file in one shot.
      amount_to_read = min(tuf.conf.CHUNK_SIZE,
                           required_length-total_downloaded)
      logger.debug('Reading next chunk...')
      data = connection.read(amount_to_read)

      # We might have no more data to read. Check number of bytes downloaded. 
      if not data:
        message = 'Downloaded '+str(total_downloaded)+'/'+ \
          str(required_length)+' bytes.'
        logger.debug(message)

        # Finally, we signal that the download is complete.
        break

      # Data successfully read from the connection.  Store it. 
      temp_file.write(data)
      total_downloaded = total_downloaded + len(data)
  except:
    raise
  else:
    return total_downloaded
  finally:
    # Whatever happens, make sure that we always close the connection.
    connection.close()





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
    logger.exception('Could not get content length about '+str(connection)+
                     ' from server!')
    reported_length = None
  finally:
    return reported_length





def _check_content_length(reported_length, required_length):
  """
  <Purpose>
    A helper function that checks whether the length reported by server is
    equal to the length we expected.
  
  <Arguments>
    reported_length:
      The total number of bytes reported by the server.

    required_length:
      The total number of bytes obtained from (possibly default) metadata.

  <Side Effects>
    No known side effects.
 
  <Exceptions>
    No known exceptions.
 
  <Returns>
    None.

  """

  try:
    if reported_length < required_length:
      logger.warn('reported_length ('+str(reported_length)+
                  ') < required_length ('+str(required_length)+')')
    elif reported_length > required_length:
      logger.warn('reported_length ('+str(reported_length)+
                  ') > required_length ('+str(required_length)+')')
    else:
      logger.debug('reported_length ('+str(reported_length)+
                   ') == required_length ('+str(required_length)+')')
  except:
    logger.exception('Could not check reported and required lengths!')




  
def _check_downloaded_length(total_downloaded, required_length,
                             STRICT_REQUIRED_LENGTH=True):
  """
  <Purpose>
    A helper function which checks whether the total number of downloaded bytes
    matches our expectation. 
 
  <Arguments>
    total_downloaded:
      The total number of bytes supposedly downloaded for the file in question.

    required_length:
      The total number of bytes expected of the file as seen from its (possibly
      default) metadata.

    STRICT_REQUIRED_LENGTH:
      A Boolean indicator used to signal whether we should perform strict
      checking of required_length. True by default. We explicitly set this to
      False when we know that we want to turn this off for downloading the
      timestamp metadata, which has no signed required_length.
  
  <Side Effects>
    None.
 
  <Exceptions>
    tuf.DownloadLengthMismatchError, if STRICT_REQUIRED_LENGTH is True and
    total_downloaded is not equal required_length.
 
  <Returns>
    None.

  """

  if total_downloaded == required_length:
    logger.debug('total_downloaded == required_length == '+
                 str(required_length))
  else:
    difference_in_bytes = abs(total_downloaded-required_length)
    message = 'Downloaded '+str(total_downloaded)+' bytes, but expected '+\
              str(required_length)+' bytes. There is a difference of '+\
              str(difference_in_bytes)+' bytes!'

    # What we downloaded is not equal to the required length, but did we ask
    # for strict checking of required length?
    if STRICT_REQUIRED_LENGTH:  
      # This must be due to a programming error, and must never happen!
      logger.error(message)          
      raise tuf.DownloadLengthMismatchError(required_length, total_downloaded)
    else:
      # We specifically disabled strict checking of required length, but we
      # will log a warning anyway. This is useful when we wish to download the
      # timestamp metadata, for which we have no signed metadata; so, we must
      # guess a reasonable required_length for it.
      logger.warn(message)





def safe_download(url, required_length):
  return _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True)





def unsafe_download(url, required_length):
  return _download_file(url, required_length, STRICT_REQUIRED_LENGTH=False)





def _download_file(url, required_length, STRICT_REQUIRED_LENGTH=True):
  """
  <Purpose>
    Given the url, hashes and length of the desired file, this function 
    opens a connection to 'url' and downloads the file while ensuring its
    length and hashes match 'required_hashes' and 'required_length'. 
 
    tuf.util.TempFile is used instead of regular tempfile object because of 
    additional functionality provided by 'tuf.util.TempFile'.
  
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
    A 'tuf.util.TempFile' object is created on disk to store the contents of
    'url'.
 
  <Exceptions>
    tuf.DownloadLengthMismatchError, if there was a mismatch of observed vs
    expected lengths while downloading the file.
 
    tuf.FormatError, if any of the arguments are improperly formatted.

    Any other unforeseen runtime exception.
 
  <Returns>
    A 'tuf.util.TempFile' file-like object which points to the contents of
    'url'.

  """

  # Do all of the arguments have the appropriate format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.URL_SCHEMA.check_match(url)
  tuf.formats.LENGTH_SCHEMA.check_match(required_length)

  # 'url.replace()' is for compatibility with Windows-based systems because
  # they might put back-slashes in place of forward-slashes.  This converts it
  # to the common format. 
  url = url.replace('\\', '/')
  logger.info('Downloading: '+str(url))

  # NOTE: Not thread-safe.
  # Save current values or functions for restoration later.
  previous_socket_timeout = socket.getdefaulttimeout()
  previous_http_response_class = httplib.HTTPConnection.response_class

  # This is the temporary file that we will return to contain the contents of
  # the downloaded file.
  temp_file = tuf.util.TempFile()

  try:
    # NOTE: Not thread-safe.
    # Set timeout to induce non-blocking socket operations.
    socket.setdefaulttimeout(tuf.conf.SOCKET_TIMEOUT)
    # Replace the socket file-like object class with our safer version.
    httplib.HTTPConnection.response_class = SaferHTTPResponse

    # Open the connection to the remote file.
    connection = _open_connection(url)

    # We ask the server about how big it thinks this file should be.
    reported_length = _get_content_length(connection)

    # Then, we check whether the required length matches the reported length.
    _check_content_length(reported_length, required_length)

    # Download the contents of the URL, up to the required length, to a
    # temporary file, and get the total number of downloaded bytes.
    total_downloaded = _download_fixed_amount_of_data(connection, temp_file, 
                                                      required_length)

    # Does the total number of downloaded bytes match the required length?
    _check_downloaded_length(total_downloaded, required_length,
                             STRICT_REQUIRED_LENGTH=STRICT_REQUIRED_LENGTH)

  except:
    # Close 'temp_file'; any written data is lost.
    temp_file.close_temp_file()
    logger.exception('Could not download URL: '+str(url))
    raise

  else:
    return temp_file

  finally:
    # NOTE: Not thread-safe.
    # Restore previously saved values or functions.
    httplib.HTTPConnection.response_class = previous_http_response_class
    socket.setdefaulttimeout(previous_socket_timeout)





