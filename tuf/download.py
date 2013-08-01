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





def _check_hashes(input_file, trusted_hashes):
  """
  <Purpose>
    Helper function that verifies multiple secure hashes of the downloaded file.
    If any of these fail it raises an exception.  This is to conform with the 
    TUF specs, which support clients with different hashing algorithms. The
    'hash.py' module is used to compute the hashes of the 'input_file'. 

  <Arguments>
    input_file:
      A file or file-like object.
    
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
  # Verify each trusted hash of 'trusted_hashes'.  Raise exception if
  # any of the hashes are incorrect and return if all are correct.
  for algorithm, trusted_hash in trusted_hashes.items():
    digest_object = tuf.hash.digest(algorithm)
    digest_object.update(input_file.read())
    computed_hash = digest_object.hexdigest()
    if trusted_hash != computed_hash:
      msg = 'Hashes do not match. Expected '+trusted_hash+' got '+computed_hash
      raise tuf.BadHashError(msg)
    else:
      logger.info('The file\'s '+algorithm+' hash is correct: '+trusted_hash)
  
  return





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

      # This is to make sure we did not make a mistake!
      #if total_downloaded > required_length:
      #  logger.error('This should NEVER happen!')
  except:
    raise
  else:
    return total_downloaded
  finally:
    connection.close()





def _get_content_length(connection):
  """
  <Purpose>
    Helper function thst get the file length from server, if any of these fail,
    the length reported by server will be simply set to None.
  
  <Arguments>
    connection:
      The object that the _open_connection returns for communicating with the
      server about the contents of a URL.
  
  <Side Effects>
    Length from server will be written to 'reported_length'.
 
  <Exceptions>
    Runtime or network exceptions will be raised without question.
 
  <Returns>
    reported_length:
      The total number of bytes reported by server.

  """

  try:
  # info().get('Content-Length') gets the length of the url file.
    reported_length = connection.info().get('Content-Length')
    reported_length = int(reported_length, 10)
  except:
    reported_length = None
   
  return reported_length





def _check_content_length(reported_length, required_length):
  """
  <Purpose>
    Helper function that checks whether the length reported by server is equal 
    to the length we expected. If the reported length is larger than we expected,
    it will rise tuf.DownloadError exception to avoid the endless data attack.
  
  <Arguments>
    reported_length:
      The total number of bytes reported by server.

    required_length:
      The total number of bytes obtained from metadata or default value.

  <Side Effects>
    None.
 
  <Exceptions>
    tuf.DownloadError, if reported_length is more than required_length.
 
  <Returns>
    None.

  """

  # The length of downloading file obtained from server is larger than which 
  # obtained from metadata or default length. So it could be a endless data 
  # attack.
  if reported_length is not None:
    if reported_length != required_length:
      if reported_length > required_length:
        message = 'Incorrect length for '+url+'. The length reported by server is'+ \
                  ' larger than expected. Expected '+str(required_length)+', got '+ \
                  str(reported_length)+' bytes. It could be an endless data attack!'
        raise tuf.DownloadError(message)
      else:
        message = 'The length reported by server is smaller than expected!'
        logger.warn(message)
    else:
      logger.info('Everything is OK. Download will start!')
  else:
     logger.warn('Server is being crappy, DownloadError will start!')





  
def _check_downloaded_length(total_downloaded, required_length, HARD_LIMIT_REQUIRED_LENGTH):
  """
  <Purpose>
    This is a helper function, which checks if the length of downloaded is equal to the length
    we expected. 
  
  <Arguments>
    reported_length:
      The total number of bytes reported by server.

    required_length:
      The total number of bytes obtained from metadata or default value.
      
    HARD_LIMIT_REQUIRED_LENGTH:
      A boolean value which indicates if the required_length passed into this 
      function is a default length.
  
  <Side Effects>
    None.
 
  <Exceptions>
    tuf.DownloadError, if HARD_LIMIT_REQUIRED_LENGTH is set to True and total_downloaded 
    is not equal required_length.
 
  <Returns>
    None.

  """

  # If the required_length is not the default value, we will check whether
  # the total_downloaded is equal to required_length.
  if HARD_LIMIT_REQUIRED_LENGTH:  
    if total_downloaded != required_length:
      message = 'Downloaded '+str(total_downloaded)+'. Expected '+str(required_length)+\
                ' for '+url+'. There are still '+str(required_length-total_downloaded)+\
                'bytes expected to be downloaded!'
      logger.error(message)          
      raise tuf.DownloadError(message)
    else:
      logger.info('Successful download!')
  
  else:  
    message = 'Required_length is default value, skip the safety check of total downloaded.'
    logger.warn(message)




def download_url_to_tempfileobj(url, required_length,
                                required_hashes=None,
                                HARD_LIMIT_REQUIRED_LENGTH=True):
  """
  <Purpose>
    Given the url, hashes and length of the desired file, this function 
    opens a connection to 'url' and downloads the file while ensuring its
    length and hashes match 'required_hashes' and 'required_length'. 
 
    tuf.util.TempFile is used instead of regular tempfile object because of 
    additional functionality provided by 'tuf.util.TempFile'.
  
  <Arguments>
    url:
      A url string that represents the location of the file. 
  
    required_hashes:
      A dictionary, where the keys represent the hashing algorithm used to 
      hash the file and the dict values the hexdigest.
  
      For instance, a hash pair might look something like this:
      {'md5': '37544f383be1fc1a32f42801c9c4b4d6'}
  
    required_length:
      An integer value representing the length of the file.

    HARD_LIMIT_REQUIRED_LENGTH:
      A boolean value which indicates if the required_length passed into this 
      function is a default length.
  
  <Side Effects>
    'tuf.util.TempFile' object is created.
 
  <Exceptions>
    tuf.DownloadError, if there was an error while downloading the file.
    
    tuf.FormatError, if any of the arguments are improperly formatted. 
 
  <Returns>
    'tuf.util.TempFile' instance.

  """

  # Do all of the arguments have the appropriate format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.URL_SCHEMA.check_match(url)
  if required_hashes is not None:
    tuf.formats.HASHDICT_SCHEMA.check_match(required_hashes)
  if required_length is not None:
    tuf.formats.LENGTH_SCHEMA.check_match(required_length)

  # 'url.replace()' is for compatibility with Windows-based systems because they 
  # might put back-slashes in place of forward-slashes.  This converts it to the
  # common format. 
  url = url.replace('\\','/')
  logger.info('Downloading: '+url)
  connection = _open_connection(url)
  temp_file = tuf.util.TempFile()

  try:
    reported_length = _get_content_length(connection)
    # call the function to check whether the length reported by server is equal 
    # to expected.
    _check_content_length(reported_length, required_length)

    # For readibility, we perform the download in a separate function, which
    # returns the total number of downloaded bytes; this number should be equal
    # to required_length. 
    total_downloaded = _download_fixed_amount_of_data(connection, temp_file, 
                                                      required_length)
    # call the function to check whether the length of total_downloaded is equal to 
    # expected.
    _check_downloaded_length(total_downloaded, required_length, HARD_LIMIT_REQUIRED_LENGTH)
      
    # We appear to have downloaded the correct amount.  Check the hashes.
    if required_hashes is not None: 
      _check_hashes(temp_file, required_hashes)

  # Exception is a base class for all non-exiting exceptions.
  except Exception, e:
    # Closing 'temp_file'.  The 'temp_file' data is destroyed.
    temp_file.close_temp_file()
    logger.error(str(e))
    raise tuf.DownloadError(e)

  return temp_file


