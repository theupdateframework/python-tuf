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
  'download_url_to_tempfileobj()' function.
  
"""

import logging
import os.path
import socket

import tuf
import tuf.hash
import tuf.util
import tuf.formats

from tuf.compatibility import httplib, ssl, urllib2, urlparse
if ssl:
    from tuf.compatibility import match_hostname
else:
    raise tuf.Error( "No SSL support!" )    # TODO: degrade gracefully


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.download')


class VerifiedHTTPSConnection( httplib.HTTPSConnection ):
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
        self.sock = ssl.wrap_socket(sock,
                                self.key_file,
                                self.cert_file,
                                cert_reqs=ssl.CERT_REQUIRED,
                                ca_certs=cert_path)

        match_hostname(self.sock.getpeercert(), self.host)


class VerifiedHTTPSHandler( urllib2.HTTPSHandler ):
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


def _get_opener( scheme = None ):
    """
    Build a urllib2 opener based on whether the user now wants SSL.

    https://github.com/pypa/pip/blob/d0fa66ecc03ab20b7411b35f7c7b423f31f77761/pip/download.py#L178
    """

    if scheme == "https":
        assert os.path.isfile( tuf.conf.ssl_certificates )

        # If we are going over https, use an opener which will provide SSL
        # certificate verification.
        https_handler = VerifiedHTTPSHandler()
        opener = urllib2.build_opener( https_handler )

        # strip out HTTPHandler to prevent MITM spoof
        for handler in opener.handlers:
            if isinstance( handler, urllib2.HTTPHandler ):
                opener.handlers.remove( handler )
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
    tuf.DownloadError
    
  <Side Effects>
    Opens a connection to a remote server.
    
  <Returns>
    File-like object.
    
  """
  
  try:
    # urllib2.Request produces a Request object that allows for a finer control 
    # of the requesting process. Request object allows to add headers or data to
    # the HTTP request. For instance, request method add_header(key, val) can be
    # used to change/spoof 'User-Agent' from default Python-urllib/x.y to 
    # 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)' this can be useful if
    # servers do not recognize connections that originates from 
    # Python-urllib/x.y.

    parsed_url = urlparse.urlparse( url )
    opener = _get_opener( scheme = parsed_url.scheme )
    request = _get_request( url )
    return opener.open( request )
  except Exception, e:
    raise tuf.DownloadError(e)





def _check_hashes(input_file, trusted_hashes=None):
  """
  <Purpose>
    A helper function that verifies multiple secure hashes of the downloaded
    file.  If any of these fail it raises an exception.  This is to conform
    with the TUF specs, which support clients with different hashing
    algorithms. The 'hash.py' module is used to compute the hashes of the
    'input_file'. 

  <Arguments>
    input_file:
      A file-like object.
    
    trusted_hashes: 
      A dictionary with hash-algorithm names as keys and hashes as dict values.
      The hashes should be in the hexdigest format.
    
  <Exceptions>
    tuf.BadHashError, if the hashes don't match.
    
  <Side Effects>
    Hash digest object is created using the 'tuf.hash' module.
    
  <Returns>
    None.

  """

  if trusted_hashes:
    # Verify each trusted hash of 'trusted_hashes'.  Raise exception if
    # any of the hashes are incorrect and return if all are correct.
    for algorithm, trusted_hash in trusted_hashes.items():
      digest_object = tuf.hash.digest(algorithm)
      digest_object.update(input_file.read())
      computed_hash = digest_object.hexdigest()
      if trusted_hash != computed_hash:
        raise tuf.BadHashError('Hashes do not match! Expected '+
                               trusted_hash+' got '+computed_hash)
      else:
        logger.info('The file\'s '+algorithm+' hash is correct: '+trusted_hash)
  else:
    logger.warn('No trusted hashes supplied to verify file at: '+
                str(input_file))





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

  # The maximum chunk of data, in bytes, we would download in every round.
  BLOCK_SIZE = 8192

  # Keep track of total bytes downloaded.
  total_downloaded = 0

  try:
    while True:
      # We download a fixed chunk of data in every round. This is so that we
      # can defend against slow retrieval attacks. Furthermore, we do not wish
      # to download an extremely large file in one shot.
      data = connection.read(min(BLOCK_SIZE, required_length-total_downloaded))

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
    tuf.DownloadError, if STRICT_REQUIRED_LENGTH is True and total_downloaded
    is not equal required_length.
 
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
      raise tuf.DownloadError(message)
    else:
      # We specifically disabled strict checking of required length, but we
      # will log a warning anyway. This is useful when we wish to download the
      # timestamp metadata, for which we have no signed metadata; so, we must
      # guess a reasonable required_length for it.
      logger.warn(message)





def download_url_to_tempfileobj(url, required_length, required_hashes=None,
                                STRICT_REQUIRED_LENGTH=True):
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
  
    required_hashes:
      A dictionary, where the keys represent the hashing algorithm used to 
      hash the file and the dict values the hexdigest.
  
      For instance, a hash pair might look something like this:
      {'md5': '37544f383be1fc1a32f42801c9c4b4d6'}

    STRICT_REQUIRED_LENGTH:
      A Boolean indicator used to signal whether we should perform strict
      checking of required_length. True by default. We explicitly set this to
      False when we know that we want to turn this off for downloading the
      timestamp metadata, which has no signed required_length.

  <Side Effects>
    A 'tuf.util.TempFile' object is created on disk to store the contents of
    'url'.
 
  <Exceptions>
    tuf.DownloadError, if there was an error while downloading the file.
 
    tuf.FormatError, if any of the arguments are improperly formatted.

    tuf.BadHashError, if the hashes don't match.

    Any other unforeseen runtime exception.
 
  <Returns>
    A 'tuf.util.TempFile' file-like object which points to the contents of
    'url'.

  """

  # Do all of the arguments have the appropriate format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.URL_SCHEMA.check_match(url)
  tuf.formats.LENGTH_SCHEMA.check_match(required_length)

  if required_hashes:
    tuf.formats.HASHDICT_SCHEMA.check_match(required_hashes)
  else:
    logger.warn('Missing hashes for: '+str(url))

  # 'url.replace()' is for compatibility with Windows-based systems because
  # they might put back-slashes in place of forward-slashes.  This converts it
  # to the common format. 
  url = url.replace('\\', '/')
  logger.info('Downloading: '+str(url))
  connection = _open_connection(url)
  temp_file = tuf.util.TempFile()

  try:
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

    # Finally, check the hashes expected of the file.
    _check_hashes(temp_file, trusted_hashes=required_hashes)

  except:
    # Something unfortunately went wrong, so we will close 'temp_file'; that
    # means any data written to it will be lost.
    temp_file.close_temp_file()
    logger.exception('Could not download URL: '+str(url))
    raise

  else:
    return temp_file





