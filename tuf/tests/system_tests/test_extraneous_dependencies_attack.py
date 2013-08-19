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
  Simulate an extraneous dependencies attack. The client attempts to download
  a file with one legitimate dependency, and one extraneous dependency.

Note: The interposition provided by 'tuf.interposition' is used to intercept
all calls made by urllib/urillib2 to certain hostnames specified in 
the interposition configuration file.  Look up interposition.py for more
information and illustration of a sample contents of the interposition 
configuration file.  Interposition was meant to make TUF integration with an
existing software updater an easy process.  This allows for more flexibility
to the existing software updater.  However, if you are planning to solely use
TUF there should be no need for interposition, all necessary calls will be
generated from within TUF.

Note: There is no difference between 'updates' and 'target' files.

"""

import os
import shutil
import urllib
import tempfile
import util_test_tools

import tuf
from tuf.interposition import urllib_tuf



# Disable logging.
util_test_tools.disable_logging()



class ExtraneousDependencyAlert(Exception):
  pass



# Interprets the contents of the file it downloads as a list of dependent
# files from the same repository
def _download(url, filename, directory, tuf=False):
  destination = os.path.join(directory, filename)
  #print 'downloading to '+destination
  #print 'from '+url
  if tuf:
    urllib_tuf.urlretrieve(url, destination)
  else:
    urllib.urlretrieve(url, destination)

  #print 'DDDDDD '+util_test_tools.read_file_content(destination)
  if util_test_tools.read_file_content(destination) != '':
    required_files = util_test_tools.read_file_content(destination).split(',')
    for required_filename in required_files:
      #print 'requires '+required_filename
      required_file_url = os.path.dirname(url)+'/'+required_filename
      _download(required_file_url, required_filename, directory, tuf)



def test_extraneous_dependency_attack(TUF=False):
  """
  <Arguments>
    TUF:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  <Purpose>
    Illustrate arbitrary package attack vulnerability.

  """

  ERROR_MSG = 'Extraneous Dependency Attack was Successful!\n'


  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # Add files to 'repo' directory: {root_repo}
    good_dependency_filepath = util_test_tools.add_file_to_repository(reg_repo, '')
    good_dependency_basename = os.path.basename(good_dependency_filepath)

    bad_dependency_filepath = util_test_tools.add_file_to_repository(reg_repo, '')
    bad_dependency_basename = os.path.basename(bad_dependency_filepath)

    # The dependent file lists the good dependency
    dependent_filepath = util_test_tools.add_file_to_repository(reg_repo, good_dependency_basename)
    dependent_basename = os.path.basename(dependent_filepath)

    url_to_repo = url+'reg_repo/'+dependent_basename
    #downloaded_file = os.path.join(downloads, dependent_basename)
    modified_dependency_list = good_dependency_basename+','+bad_dependency_basename

    if TUF:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+dependent_basename

      # Attacker adds the dependency in the targets repository.
      target = os.path.join(targets_dir, dependent_basename)
      util_test_tools.modify_file_at_repository(target, modified_dependency_list)

    # Attacker adds the dependency in the regular repository.
    util_test_tools.modify_file_at_repository(dependent_filepath, modified_dependency_list)

    # End of Setup.


    try:
      # Client downloads (tries to download) the file.
      _download(url=url_to_repo, filename=dependent_basename, directory=downloads, tuf=TUF)

    except tuf.DownloadError:
      # If tuf.DownloadError is raised, this means that TUF has prevented
      # the download of an unrecognized file.  Enable the logging to see,
      # what actually happened.
      pass

    else:
      # Check if the legitimate dependency was downloaded
      if not(os.path.exists(os.path.join(downloads, good_dependency_basename))):
        raise tuf.DownloadError

      # Check if the extraneous dependency was downloaded
      if os.path.exists(os.path.join(downloads, bad_dependency_basename)):
        raise ExtraneousDependencyAlert(ERROR_MSG)


  finally:
    util_test_tools.cleanup(root_repo, server_proc)



print 'Attempting extraneous dependency attack without TUF:'
try:
  test_extraneous_dependency_attack(TUF=False)
  
except ExtraneousDependencyAlert, error:
  print error



print 'Attempting extraneous dependency attack with TUF:'
try:
  test_extraneous_dependency_attack(TUF=True)

except ExtraneousDependencyAlert, error:
  print error
