#!/usr/bin/env python

"""
<Program Name>
  test_extraneous_dependencies_attack.py

<Author>
  Zane Fisher

<Started>
  August 19, 2013

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate an extraneous dependencies attack.  The client attempts to download
  a file, which lists all the target dependencies, with one legitimate
  dependency, and one extraneous dependency.  A client should not download a
  target dependency even if it is found on the repository.  Valid targets are
  listed and verified by TUF metadata, such as 'targets.txt'.

  Target dependencies listed in the file are comma-separated.

  Note: The interposition provided by 'tuf.interposition' is used to intercept
  all calls made by urllib/urillib2 to certain hostnames specified in 
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


class ExtraneousDependencyAlert(Exception):
  pass



# Interpret anything following 'requires:' in the contents of the file it
# downloads as a comma-separated list of dependent files from the same repository.
def _download(url, filename, directory, using_tuf=False):
  destination = os.path.join(directory, filename)
  if using_tuf:
    tuf.interposition.urllib_tuf.urlretrieve(url, destination)
  else:
    urllib.urlretrieve(url, destination)

  file_contents = util_test_tools.read_file_content(destination)

  # Parse the list of required files (if it exists) and download them.
  if file_contents.find('requires:') != -1:
    required_files = file_contents[file_contents.find('requires:') + 9:].split(',')
    for required_filename in required_files:
      required_file_url = os.path.dirname(url)+os.sep+required_filename
      _download(required_file_url, required_filename, directory, using_tuf)



def test_extraneous_dependency_attack(using_tuf=False):
  """
  <Purpose>
    Illustrate extraneous dependency attack vulnerability.

  <Arguments>
    using_tuf:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  """

  ERROR_MSG = 'Extraneous Dependency Attack was Successful!'

  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(using_tuf)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # Add files to 'repo' directory: {root_repo}.
    good_dependency_filepath = util_test_tools.add_file_to_repository(reg_repo,
                                          'the file you need')
    good_dependency_basename = os.path.basename(good_dependency_filepath)

    bad_dependency_filepath = util_test_tools.add_file_to_repository(reg_repo,
                                          'the file you don\'t need')
    bad_dependency_basename = os.path.basename(bad_dependency_filepath)

    # The dependent file lists the good dependency.
    dependent_filepath = util_test_tools.add_file_to_repository(reg_repo,
                                          'requires:'+good_dependency_basename)
    dependent_basename = os.path.basename(dependent_filepath)

    url_to_repo = url+'reg_repo/'+dependent_basename

    # List the bad dependency first. If an attacker modifies a target by
    # simply appending the file contents, tuf.download will ignore the appended
    # data, downloading only as much data as the TUF metadata says the target
    # should contain.
    modified_dependency_list = bad_dependency_basename+','+\
      good_dependency_basename

    if using_tuf:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+dependent_basename

      # Attacker modifies the depenent file in the targets repository, adding
      # the bad dependency to its list.
      dependent_target_filepath = os.path.join(targets_dir, dependent_basename)
      util_test_tools.modify_file_at_repository(dependent_target_filepath,
                                        'requires:'+modified_dependency_list)

    # Attacker modifies the depenent file in the regular repository, adding
    # the bad dependency to its list.
    util_test_tools.modify_file_at_repository(dependent_filepath,
                                        'requires:'+modified_dependency_list)

    # End of Setup.


    try:
      # Client downloads (tries to download) the file.
      _download(url_to_repo, dependent_basename, downloads, using_tuf)

    except tuf.NoWorkingMirrorError, error:
      # We only set up one mirror, so if it fails, we expect a
      # NoWorkingMirrorError. If TUF has worked as intended, the mirror error
      # contained within should be a BadHashError.
      mirror_error = \
              error.mirror_errors[url+'tuf_repo/targets/'+dependent_basename]

      assert isinstance(mirror_error, tuf.BadHashError)

    else:
      # Check if the legitimate dependency was downloaded.
      if not(os.path.exists(os.path.join(downloads, good_dependency_basename))):
        raise tuf.DownloadError

      # Check if the extraneous dependency was downloaded.
      if os.path.exists(os.path.join(downloads, bad_dependency_basename)):
        raise ExtraneousDependencyAlert(ERROR_MSG)
  
  finally:
    util_test_tools.cleanup(root_repo, server_proc)



print('Attempting extraneous dependency attack without TUF:')
try:
  test_extraneous_dependency_attack(using_tuf=False)
  
except ExtraneousDependencyAlert, error:
  print(error)
else:
  print('Extraneous dependency attack failed.')
print()

print('Attempting extraneous dependency attack with TUF:')
try:
  test_extraneous_dependency_attack(using_tuf=True)

except ExtraneousDependencyAlert, error:
  print(error)
else:
  print('Extraneous dependency attack failed.')
print()
