#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program>
  test_download.py

<Author>
  Konstantin Andrianov.

<Started>
  March 26, 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit test for 'download.py'.

  NOTE: Make sure test_download.py is ran in 'tuf/tests/' directory.
  Otherwise, module that launches simple server would not be found.

  TODO: Adopt the environment variable management from test_proxy_use.py here.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import hashlib
import logging
import os
import sys
import unittest
import urllib3
import warnings

import tuf
import tuf.download as download
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.exceptions

from tests import utils

import requests.exceptions

import securesystemslib

logger = logging.getLogger(__name__)


class TestDownload(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """
    Create a temporary file and launch a simple server in the
    current working directory.
    """

    unittest_toolbox.Modified_TestCase.setUp(self)

    # Making a temporary file.
    current_dir = os.getcwd()
    target_filepath = self.make_temp_data_file(directory=current_dir)
    self.target_fileobj = open(target_filepath, 'r')
    self.target_data = self.target_fileobj.read()
    self.target_data_length = len(self.target_data)

    # Launch a SimpleHTTPServer (serves files in the current dir).
    self.server_process_handler = utils.TestServerProcess(log=logger)

    rel_target_filepath = os.path.basename(target_filepath)
    self.url = 'http://localhost:' \
        + str(self.server_process_handler.port) + '/' + rel_target_filepath

    # Computing hash of target file data.
    m = hashlib.md5()
    m.update(self.target_data.encode('utf-8'))
    digest = m.hexdigest()
    self.target_hash = {'md5':digest}


  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)

    # Cleans the resources and flush the logged lines (if any).
    self.server_process_handler.clean()

    self.target_fileobj.close()


  # Test: Normal case.
  def test_download_url_to_tempfileobj(self):

    download_file = download.safe_download
    with download_file(self.url, self.target_data_length) as temp_fileobj:
      temp_fileobj.seek(0)
      temp_file_data = temp_fileobj.read().decode('utf-8')
      self.assertEqual(self.target_data, temp_file_data)
      self.assertEqual(self.target_data_length, len(temp_file_data))



  # Test: Incorrect lengths.
  def test_download_url_to_tempfileobj_and_lengths(self):
    # We do *not* catch
    # 'securesystemslib.exceptions.DownloadLengthMismatchError' in the
    # following two calls because the file at 'self.url' contains enough bytes
    # to satisfy the smaller number of required bytes requested.
    # safe_download() and unsafe_download() will only log a warning when the
    # the server-reported length of the file does not match the
    # required_length.  'updater.py' *does* verify the hashes of downloaded
    # content.
    download.safe_download(self.url, self.target_data_length - 4).close()
    download.unsafe_download(self.url, self.target_data_length - 4).close()

    # We catch 'tuf.exceptions.DownloadLengthMismatchError' for safe_download()
    # because it will not download more bytes than requested (in this case, a
    # length greater than the size of the target file).
    self.assertRaises(tuf.exceptions.DownloadLengthMismatchError,
        download.safe_download, self.url, self.target_data_length + 1)

    # Calling unsafe_download() with a mismatched length should not raise an
    # exception.
    download.unsafe_download(self.url, self.target_data_length + 1).close()



  def test_download_url_to_tempfileobj_and_performance(self):

    """
    # Measuring performance of 'auto_flush = False' vs. 'auto_flush = True'
    # in download._download_file() during write. No change was observed.
    star_cpu = time.clock()
    star_real = time.time()

    temp_fileobj = download_file(self.url,
                                 self.target_data_length)

    end_cpu = time.clock()
    end_real = time.time()

    self.assertEqual(self.target_data, temp_fileobj.read())
    self.assertEqual(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close()

    print "Performance cpu time: "+str(end_cpu - star_cpu)
    print "Performance real time: "+str(end_real - star_real)

    # TODO: [Not urgent] Show the difference by setting write(auto_flush=False)
    """


  # Test: Incorrect/Unreachable URLs.
  def test_download_url_to_tempfileobj_and_urls(self):

    download_file = download.safe_download
    unsafe_download_file = download.unsafe_download

    self.assertRaises(securesystemslib.exceptions.FormatError,
                      download_file, None, self.target_data_length)

    self.assertRaises(tuf.exceptions.URLParsingError,
                      download_file,
                      self.random_string(), self.target_data_length)

    url = 'http://localhost:' \
        + str(self.server_process_handler.port) + '/' + self.random_string()
    self.assertRaises(requests.exceptions.HTTPError,
                      download_file,
                      url,
                      self.target_data_length)
    url1 = 'http://localhost:' \
      + str(self.server_process_handler.port + 1) + '/' + self.random_string()
    self.assertRaises(requests.exceptions.ConnectionError,
                      download_file,
                      url1,
                      self.target_data_length)

    # Specify an unsupported URI scheme.
    url_with_unsupported_uri = self.url.replace('http', 'file')
    self.assertRaises(requests.exceptions.InvalidSchema, download_file, url_with_unsupported_uri,
                      self.target_data_length)
    self.assertRaises(requests.exceptions.InvalidSchema, unsafe_download_file,
                      url_with_unsupported_uri, self.target_data_length)





  '''
  # This test uses sites on the internet, requiring a net connection to succeed.
  # Since this is the only such test in TUF, I'm not going to enable it... but
  # it's here in case it's useful for diagnosis.
  def test_https_validation(self):
    """
    Use some known URLs on the net to ensure that TUF download checks SSL
    certificates appropriately.
    """
    # We should never get as far as the target file download itself, so the
    # length we pass to safe_download and unsafe_download shouldn't matter.
    irrelevant_length = 10

    for bad_url in [
        'https://expired.badssl.com/', # expired certificate
        'https://wrong.host.badssl.com/', ]: # hostname verification fail

      with self.assertRaises(requests.exceptions.SSLError):
        download.safe_download(bad_url, irrelevant_length)

      with self.assertRaises(requests.exceptions.SSLError):
        download.unsafe_download(bad_url, irrelevant_length)
  '''




  def test_https_connection(self):
    """
    Try various HTTPS downloads using trusted and untrusted certificates with
    and without the correct hostname listed in the SSL certificate.
    """
    # Make a temporary file to be served to the client.
    current_directory = os.getcwd()
    target_filepath = self.make_temp_data_file(directory=current_directory)

    with open(target_filepath, 'r') as target_file_object:
      target_data_length = len(target_file_object.read())

    # These cert files provide various test cases:
    # good:    A valid cert from an older generation of test_download.py tests.
    # good2:   A valid cert made simultaneous to the bad certs below, with the
    #          same settings otherwise, tested here in case the difference
    #          between the way the new bad certs and the old good cert were
    #          generated turns out to matter at some point.
    # bad:     An otherwise-valid cert with the wrong hostname. The good certs
    #          list "localhost", but this lists "notmyhostname".
    # expired: An otherwise-valid cert but which is expired (no valid dates
    #          exist, fwiw: startdate > enddate).
    good_cert_fname = os.path.join('ssl_certs', 'ssl_cert.crt')
    good2_cert_fname = os.path.join('ssl_certs', 'ssl_cert_2.crt')
    bad_cert_fname = os.path.join('ssl_certs', 'ssl_cert_wronghost.crt')
    expired_cert_fname = os.path.join('ssl_certs', 'ssl_cert_expired.crt')

    # Launch four HTTPS servers (serve files in the current dir).
    # 1: we expect to operate correctly
    # 2: also good; uses a slightly different cert (controls for the cert
    #    generation method used for the next two, in case it comes to matter)
    # 3: run with an HTTPS certificate with an unexpected hostname
    # 4: run with an HTTPS certificate that is expired
    # Be sure to offset from the port used in setUp to avoid collision.


    good_https_server_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py',
        extra_cmd_args=[good_cert_fname])
    good2_https_server_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py',
        extra_cmd_args=[good2_cert_fname])
    bad_https_server_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py',
        extra_cmd_args=[bad_cert_fname])
    expd_https_server_handler = utils.TestServerProcess(log=logger,
        server='simple_https_server.py',
        extra_cmd_args=[expired_cert_fname])

    suffix = '/' +  os.path.basename(target_filepath)
    good_https_url = 'https://localhost:' \
        + str(good_https_server_handler.port) + suffix
    good2_https_url = 'https://localhost:' \
        + str(good2_https_server_handler.port) + suffix
    bad_https_url = 'https://localhost:' \
        + str(bad_https_server_handler.port) + suffix
    expired_https_url = 'https://localhost:' \
        + str(expd_https_server_handler.port) + suffix

    # Download the target file using an HTTPS connection.

    # Use try-finally solely to ensure that the server processes are killed.
    try:
      # Trust the certfile that happens to use a different hostname than we
      # will expect.
      os.environ['REQUESTS_CA_BUNDLE'] = bad_cert_fname
      # Clear sessions to ensure that the certificate we just specified is used.
      # TODO: Confirm necessity of this session clearing and lay out mechanics.
      tuf.download._sessions = {}

      # Try connecting to the server process with the bad cert while trusting
      # the bad cert. Expect failure because even though we trust it, the
      # hostname we're connecting to does not match the hostname in the cert.
      logger.info('Trying HTTPS download of target file: ' + bad_https_url)
      with warnings.catch_warnings():
        # We're ok with a slightly fishy localhost cert
        warnings.filterwarnings('ignore',
            category=urllib3.exceptions.SubjectAltNameWarning)

        with self.assertRaises(requests.exceptions.SSLError):
          download.safe_download(bad_https_url, target_data_length)
        with self.assertRaises(requests.exceptions.SSLError):
          download.unsafe_download(bad_https_url, target_data_length)

        # Try connecting to the server processes with the good certs while not
        # trusting the good certs (trusting the bad cert instead). Expect failure
        # because even though the server's cert file is otherwise OK, we don't
        # trust it.
        logger.info('Trying HTTPS download of target file: ' + good_https_url)
        with self.assertRaises(requests.exceptions.SSLError):
          download.safe_download(good_https_url, target_data_length)
        with self.assertRaises(requests.exceptions.SSLError):
          download.unsafe_download(good_https_url, target_data_length)

        logger.info('Trying HTTPS download of target file: ' + good2_https_url)
        with self.assertRaises(requests.exceptions.SSLError):
          download.safe_download(good2_https_url, target_data_length)
        with self.assertRaises(requests.exceptions.SSLError):
          download.unsafe_download(good2_https_url, target_data_length)


        # Configure environment to now trust the certfile that is expired.
        os.environ['REQUESTS_CA_BUNDLE'] = expired_cert_fname
        # Clear sessions to ensure that the certificate we just specified is used.
        # TODO: Confirm necessity of this session clearing and lay out mechanics.
        tuf.download._sessions = {}

        # Try connecting to the server process with the expired cert while
        # trusting the expired cert. Expect failure because even though we trust
        # it, it is expired.
        logger.info('Trying HTTPS download of target file: ' + expired_https_url)
        with self.assertRaises(requests.exceptions.SSLError):
          download.safe_download(expired_https_url, target_data_length)
        with self.assertRaises(requests.exceptions.SSLError):
          download.unsafe_download(expired_https_url, target_data_length)


        # Try connecting to the server processes with the good certs while
        # trusting the appropriate good certs. Expect success.
        # TODO: expand testing to switch expected certificates back and forth a
        #       bit more while clearing / not clearing sessions.
        os.environ['REQUESTS_CA_BUNDLE'] = good_cert_fname
        # Clear sessions to ensure that the certificate we just specified is used.
        # TODO: Confirm necessity of this session clearing and lay out mechanics.
        tuf.download._sessions = {}
        logger.info('Trying HTTPS download of target file: ' + good_https_url)
        download.safe_download(good_https_url, target_data_length).close()
        download.unsafe_download(good_https_url, target_data_length).close()

        os.environ['REQUESTS_CA_BUNDLE'] = good2_cert_fname
        # Clear sessions to ensure that the certificate we just specified is used.
        # TODO: Confirm necessity of this session clearing and lay out mechanics.
        tuf.download._sessions = {}
        logger.info('Trying HTTPS download of target file: ' + good2_https_url)
        download.safe_download(good2_https_url, target_data_length).close()
        download.unsafe_download(good2_https_url, target_data_length).close()

    finally:
      for proc_handler in [
          good_https_server_handler,
          good2_https_server_handler,
          bad_https_server_handler,
          expd_https_server_handler]:

        # Cleans the resources and flush the logged lines (if any).
        proc_handler.clean()



# Run unit test.
if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
