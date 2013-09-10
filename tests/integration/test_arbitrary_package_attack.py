"""
<Program Name>
  test_arbitrary_package_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate an arbitrary package attack.  A simple client update vs. client
  update implementing TUF.

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

import tuf
from tuf.interposition import urllib_tuf
from tuf.tests import util_test_tools



class ArbitraryPackageAlert(Exception):
  pass



def _download(url, filename, tuf=False):
  if tuf:
    urllib_tuf.urlretrieve(url, filename)

  else:
    urllib.urlretrieve(url, filename)





def test_arbitrary_package_attack(TUF=False):
  """
  <Arguments>
    TUF:
      If set to 'False' all directories that start with 'tuf_' are ignored, 
      indicating that tuf is not implemented.

  <Purpose>
    Illustrate arbitrary package attack vulnerability.

  """

  ERROR_MSG = 'Arbitrary Package Attack was Successful!\n'


  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    targets_dir = os.path.join(tuf_repo, 'targets')

    # Add a file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'Test A')
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    if TUF:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Modify the url.  Remember that the interposition will intercept 
      # urls that have 'localhost:9999' hostname, which was specified in
      # the json interposition configuration file.  Look for 'hostname'
      # in 'util_test_tools.py'. Further, the 'file_basename' is the target
      # path relative to 'targets_dir'. 
      url_to_repo = 'http://localhost:9999/'+file_basename

      # Attacker modifies the file at the targets repository.
      target = os.path.join(targets_dir, file_basename)
      util_test_tools.modify_file_at_repository(target, 'Evil A')

    # Attacker modifies the file at the regular repository.
    util_test_tools.modify_file_at_repository(filepath, 'Evil A')

    # End of Setup.


    try:
      # Client downloads (tries to download) the file.
      _download(url=url_to_repo, filename=downloaded_file, tuf=TUF)

    except tuf.DownloadError:
      # If tuf.DownloadError is raised, this means that TUF has prevented
      # the download of an unrecognized file.  Enable the logging to see,
      # what actually happened.
      pass

    else:
      # Check whether the attack succeeded by inspecting the content of the
      # update.  The update should contain 'Test A'.  Technically it suffices
      # to check whether the file was downloaded or not.
      downloaded_content = util_test_tools.read_file_content(downloaded_file)
      if 'Test A' != downloaded_content:
        raise ArbitraryPackageAlert(ERROR_MSG)


  finally:
    util_test_tools.cleanup(root_repo, server_proc)





try:
  test_arbitrary_package_attack(TUF=False)

except ArbitraryPackageAlert, error:
  print error



try:
  test_arbitrary_package_attack(TUF=True)

except ArbitraryPackageAlert, error:
  print error
