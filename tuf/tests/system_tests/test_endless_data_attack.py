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
all calls made by urllib/urillib2 to certain network locations specified in 
the interposition configuration file.  Look up interposition.py for more
information and illustration of a sample contents of the interposition 
configuration file.  Interposition was meant to make TUF integration with an
existing software updater an easy process.  This allows for more flexibility
to the existing software updater.  However, if you are planning to solely use
TUF there should be no need for interposition, all necessary calls will be
generated from within TUF.

Note: There is no difference between 'updates' and 'target' files.

"""

# TODO:...

import os
import shutil
import urllib
import tempfile
import util_test_tools

from tuf.interposition import urllib_tuf

# Disable logging.
util_test_tools.disable_logging()


class TestSetupError(Exception):
  pass

class EndlessDataAttack(Exception):
  pass



def download(url, filename, tuf=False):
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
    Illustrate endless data attack vulnerability.

  """

  try:
    # Setup.
    root_repo, url, server_proc, keyids = util_test_tools.init_repo(tuf=TUF)
    reg_repo = os.path.join(root_repo, 'reg_repo')
    tuf_repo = os.path.join(root_repo, 'tuf_repo')
    downloads = os.path.join(root_repo, 'downloads')
    tuf_targets = os.path.join(tuf_repo, 'targets')

    # Add a file to 'repo' directory: {root_repo}
    filepath = util_test_tools.add_file_to_repository(reg_repo, 'Test A')
    file_basename = os.path.basename(filepath)
    url_to_repo = url+'reg_repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    # Refresh the tuf repository and apply tuf interpose.
    if TUF:
      # Update TUF metadata before attacker modifies anything.
      util_test_tools.tuf_refresh_repo(root_repo, keyids)

      # Attacker modifies the file at the targets repository.
      target = os.path.join(tuf_targets, file_basename)
      endless_data = 'A'*1000
      util_test_tools.modify_file_at_repository(target, endless_data)

    # Attacker modifies the file at the regular repository.
    util_test_tools.modify_file_at_repository(filepath, endless_data)

    # End Setup.

    # Client downloads (tries to download) the file.
    download(url=url_to_repo, filename=downloaded_file, tuf=TUF)

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'Test A'.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    msg = 'Endless Data Attack was successful!\n'
    print downloaded_content
    if 'Test A' != downloaded_content:
      raise EndlessDataAttack(msg)

  finally:
    pass
    util_test_tools.cleanup(root_repo, server_proc)




try:
  test_arbitrary_package_attack(TUF=False)
except EndlessDataAttack, error:
  print error

try:
  test_arbitrary_package_attack(TUF=True)
except EndlessDataAttack, error:
  print error