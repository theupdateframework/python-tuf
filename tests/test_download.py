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
import random
import subprocess
import time
import unittest

import tuf
import tuf.download as download
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.exceptions

import requests.exceptions

import securesystemslib
import six

logger = logging.getLogger('tuf.test_download')


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
    self.PORT = random.randint(30000, 45000)
    command = ['python', 'simple_server.py', str(self.PORT)]
    self.server_proc = subprocess.Popen(command, stderr=subprocess.PIPE)
    logger.info('\n\tServer process started.')
    logger.info('\tServer process id: '+str(self.server_proc.pid))
    logger.info('\tServing on port: '+str(self.PORT))
    junk, rel_target_filepath = os.path.split(target_filepath)
    self.url = 'http://localhost:'+str(self.PORT)+'/'+rel_target_filepath

    # NOTE: Following error is raised if delay is not applied:
    #    <urlopen error [Errno 111] Connection refused>
    time.sleep(1)

    # Computing hash of target file data.
    m = hashlib.md5()
    m.update(self.target_data.encode('utf-8'))
    digest = m.hexdigest()
    self.target_hash = {'md5':digest}


  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)
    if self.server_proc.returncode is None:
      logger.info('\tServer process '+str(self.server_proc.pid)+' terminated.')
      self.server_proc.kill()
    self.target_fileobj.close()


  # Test: Normal case.
  def test_download_url_to_tempfileobj(self):

    download_file = download.safe_download

    temp_fileobj = download_file(self.url, self.target_data_length)
    self.assertEqual(self.target_data, temp_fileobj.read().decode('utf-8'))
    self.assertEqual(self.target_data_length, len(temp_fileobj.read()))
    temp_fileobj.close_temp_file()



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
    download.safe_download(self.url, self.target_data_length - 4)
    download.unsafe_download(self.url, self.target_data_length - 4)

    # We catch 'tuf.exceptions.DownloadLengthMismatchError' for safe_download()
    # because it will not download more bytes than requested (in this case, a
    # length greater than the size of the target file).
    self.assertRaises(tuf.exceptions.DownloadLengthMismatchError,
        download.safe_download, self.url, self.target_data_length + 1)

    # Calling unsafe_download() with a mismatched length should not raise an
    # exception.
    download.unsafe_download(self.url, self.target_data_length + 1)



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
    temp_fileobj.close_temp_file()

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

    self.assertRaises(requests.exceptions.HTTPError,
                      download_file,
                      'http://localhost:' + str(self.PORT) + '/' + self.random_string(),
                      self.target_data_length)

    self.assertRaises(requests.exceptions.ConnectionError,
                      download_file,
                      'http://localhost:' + str(self.PORT+1) + '/' + self.random_string(),
                      self.target_data_length)

    # Specify an unsupported URI scheme.
    url_with_unsupported_uri = self.url.replace('http', 'file')
    self.assertRaises(requests.exceptions.InvalidSchema, download_file, url_with_unsupported_uri,
                      self.target_data_length)
    self.assertRaises(requests.exceptions.InvalidSchema, unsafe_download_file,
                      url_with_unsupported_uri, self.target_data_length)





  # This test uses sites on the internet, requiring a net connection to succeed.
  # Since this is the only such test in TUF, I'm not going to enable it... but
  # it's here in case it's useful for diagnosis.
  # def test_https_validation(self):
  #   """
  #   Use some known URLs on the net to ensure that TUF download checks SSL
  #   certificates appropriately.
  #   """
  #   # We should never get as far as the target file download itself, so the
  #   # length we pass to safe_download and unsafe_download shouldn't matter.
  #   irrelevant_length = 10
  #
  #   for bad_url in [
  #       'https://expired.badssl.com/', # expired certificate
  #       'https://wrong.host.badssl.com/', ]: # hostname verification fail
  #
  #     with self.assertRaises(requests.exceptions.SSLError):
  #       download.safe_download(bad_url, irrelevant_length)
  #
  #     with self.assertRaises(requests.exceptions.SSLError):
  #       download.unsafe_download(bad_url, irrelevant_length)





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

    # These cert files should both be valid, but "good" lists localhost and
    # "bad" lists another hostname. We'll be trying to download from localhost,
    # so we expect
    good_cert_fname = 'ssl_cert.crt'
    bad_cert_fname = 'ssl_cert_wronghost.crt'

    # Launch two https servers (serves files in the current dir).
    # The first we expect to operate correctly, and the second we run with an
    # HTTPS certificate with an unexpected hostname.
    port1 = str(random.randint(30000, 45000))
    port2 = str(int(port1) + 1)
    command1 = ['python', 'simple_https_server.py', port1, good_cert_fname]
    command2 = ['python', 'simple_https_server.py', port2, bad_cert_fname]
    good_https_server_proc = subprocess.Popen(command1, stderr=subprocess.PIPE)
    bad_https_server_proc = subprocess.Popen(command2, stderr=subprocess.PIPE)

    # NOTE: Following error is raised if delay is not applied:
    #    <urlopen error [Errno 111] Connection refused>
    time.sleep(0.2)

    relative_target_fpath = os.path.basename(target_filepath)
    good_https_url = 'https://localhost:' + port1 + '/' + relative_target_fpath
    bad_https_url = good_https_url.replace(':' + port1, ':' + port2)


    # Download the target file using an https connection.

    # Use try-finally solely to ensure that the server processes are killed.
    try:
      # Trust the certfile that happens to use a different hostname than we
      # will expect.
      os.environ['REQUESTS_CA_BUNDLE'] = bad_cert_fname

      # Try connecting to the server process with the bad cert while trusting
      # the bad cert. Expect failure because even though we trust it, the
      # hostname we're connecting to does not match the hostname in the cert.
      logger.info('Trying https download of target file: ' + bad_https_url)
      with self.assertRaises(requests.exceptions.SSLError):
        download.safe_download(bad_https_url, target_data_length)
      with self.assertRaises(requests.exceptions.SSLError):
        download.unsafe_download(bad_https_url, target_data_length)

      # Try connecting to the server process with the good cert while not
      # trusting the good cert (trusting the bad cert instead). Expect failure
      # because even though the server's cert file is otherwise OK, we don't
      # trust it.
      print('Trying https download of target file: ' + good_https_url)
      with self.assertRaises(requests.exceptions.SSLError):
        download.safe_download(good_https_url, target_data_length)
      with self.assertRaises(requests.exceptions.SSLError):
        download.unsafe_download(good_https_url, target_data_length)

      # Configure environment to trust the good cert file now instead.
      os.environ['REQUESTS_CA_BUNDLE'] = good_cert_fname

      # Try connecting to the server process with the good cert while trusting
      # that cert. Expect success.
      # Note: running these OK downloads at the top of this try section causes
      #       a failure in a previous assertion: retrieving the same good URL
      #       again after no longer "trusting" the good certfile still succeeds
      #       if we had previously succeeded in retrieving that same URL while
      #       still trusting the good cert. Perhaps it's a caching issue....?
      #       I'm not especially concerned yet, but take note for later....
      logger.info('Trying https download of target file: ' + good_https_url)
      download.safe_download(good_https_url, target_data_length)
      download.unsafe_download(good_https_url, target_data_length)

    finally:
      if good_https_server_proc.returncode is None:
        logger.info(
            'Terminating server process ' + str(good_https_server_proc.pid))
        good_https_server_proc.kill()

      if bad_https_server_proc.returncode is None:
        logger.info(
            'Terminating server process ' + str(bad_https_server_proc.pid))
        bad_https_server_proc.kill()





  def test__get_content_length(self):
    content_length = \
      tuf.download._get_content_length({'bad_connection_object': 8})
    self.assertEqual(content_length, None)


# Run unit test.
if __name__ == '__main__':
  unittest.main()
