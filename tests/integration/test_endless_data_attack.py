#!/usr/bin/env python

"""
<Program Name>
  test_endless_data_attack.py

<Author>
  Konstantin Andrianov

<Started>
  March 13, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate an endless data attack.  A simple client update vs. client
  update implementing TUF.

  Note: The interposition provided by 'tuf.interposition' is used to intercept
  all calls made by urllib/urillib2 to certain hostname specified in 
  the interposition configuration file.  Look up interposition.py for more
  information and illustration of a sample contents of the interposition 
  configuration file.  Interposition was meant to make TUF integration with an
  existing software updater an easy process.  This allows for more flexibility
  to the existing software updater.  However, if you are planning to solely use
  TUF there should be no need for interposition, all necessary calls will be
  generated from within TUF.

  There is no difference between 'updates' and 'target' files.

"""

# Help with Python 3 compatability, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import os
import urllib

import tuf
import tuf.interposition
import tuf.tests.util_test_tools as util_test_tools



class EndlessDataAttack(Exception):
  pass



def _download(url, filename, using_tuf=False):
  if using_tuf:
    tuf.interposition.urllib_tuf.urlretrieve(url, filename)
  else:
    urllib.urlretrieve(url, filename)



def test_endless_data_attack(using_tuf=False, TIMESTAMP=False):
  """
  <Purpose>
    Illustrate endless data attack vulnerability.

  <Arguments>
    using_tuf:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  """

  ERROR_MSG = 'Endless Data Attack was Successful!\n'

  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(using_tuf)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    tuf_targets = os.path.join(tuf_repo, 'targets')

    # Original data.
    INTENDED_DATA = 'Test A'

    # Add a file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, INTENDED_DATA)
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)
    # We do not deliver truly endless data, but we will extend the original
    # file by many bytes.
    noisy_data = 'X'*100000


    if using_tuf:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)
      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+file_basename

      # Attacker modifies the file at the targets repository.
      target = os.path.join(tuf_targets, file_basename)
      original_data = util_test_tools.read_file_content(target)
      larger_original_data = original_data + noisy_data
      util_test_tools.modify_file_at_repository(target, larger_original_data)

      # Attacker modifies the timestamp.txt metadata.
      if TIMESTAMP:
        metadata = os.path.join(tuf_repo, 'metadata')
        timestamp = os.path.join(metadata, 'timestamp.txt')
        original_data = util_test_tools.read_file_content(timestamp)
        larger_original_data = original_data + noisy_data
        util_test_tools.modify_file_at_repository(timestamp,
                                                  larger_original_data)

    # Attacker modifies the file at the regular repository.
    original_data = util_test_tools.read_file_content(filepath)
    larger_original_data = original_data + noisy_data
    util_test_tools.modify_file_at_repository(filepath, larger_original_data)

    # End Setup.


    # Client downloads (tries to download) the file.
    try:
      _download(url_to_repo, downloaded_file, using_tuf)
    except Exception, exception:
      # Because we are extending the true timestamp TUF metadata with invalid
      # JSON, we except to catch an error about invalid metadata JSON.
      if using_tuf and TIMESTAMP:
        endless_data_attack = False

        for mirror_url, mirror_error in exception.mirror_errors.iteritems():
          if isinstance(mirror_error, tuf.InvalidMetadataJSONError):
            endless_data_attack = True
            break

        # In case we did not detect what was likely an endless data attack, we
        # reraise the exception to indicate that endless data attack detection
        # failed.
        if not endless_data_attack: raise
      else: raise

    # When we test downloading "endless" timestamp with TUF, we want to skip
    # the following test because downloading the timestamp should have failed.
    if not (using_tuf and TIMESTAMP):
      # Check whether the attack succeeded by inspecting the content of the
      # update.  The update should contain 'Test A'.  Technically it suffices
      # to check whether the file was downloaded or not.
      downloaded_content = util_test_tools.read_file_content(downloaded_file)
      if downloaded_content != INTENDED_DATA:
        raise EndlessDataAttack(ERROR_MSG)

  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_endless_data_attack(using_tuf=False, TIMESTAMP=False)
except EndlessDataAttack, error:
  print('Endless data attack worked on download without TUF!')

try:
  test_endless_data_attack(using_tuf=True, TIMESTAMP=False)
except EndlessDataAttack, error:
  print('Endless data attack worked on download without TUF!')
  print(str(error))
else:
  print('Endless data attack did not work on download with TUF!')

try:
  # This test fails because the timestamp metadata has been extended with
  # random data from its true length, thereby resulting in invalid JSON.
  test_endless_data_attack(using_tuf=True, TIMESTAMP=True)
except EndlessDataAttack, error:
  print('Endless data attack worked on download without TUF!')
  print(str(error))
else:
  print('Endless data attack did not work on download with TUF!')
