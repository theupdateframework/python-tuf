"""
<Program Name>
  test_replay_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate a replay attack.  A simple client update vs. client update 
  implementing TUF.

  Note: It's assumed that attacker does NOT have access to metadata signing
  keys.  Keep them safe!

  Note: There is no difference between 'updates' and 'target' files.

<Usage>
  To implement TUF use one of the following options: '-t', '--tuf', '--TUF'
  Ex. $python test_replay_attack.py --tuf

  To simply run the a client update without implementing TUF omit the options.
  Ex. $python test_replay_attack.py
"""

import os
import shutil
import test_system_setup
import unittest
import tempfile
import optparse


# Was the option set?
test_system_setup.tuf_option()


class TestReplayAttack(test_system_setup.TestCase):
  # Whenever attack succeeds print following message:
  msg = 'Replay attack was succeeded!\n'


  def setUp(self):
    test_system_setup.TestCase.setUp(self)
    self.evil_dir = tempfile.mkdtemp(dir=os.getcwd())
    shutil.copy(self.filepath1, self.evil_dir)
    fileobj = open(self.filepath1, 'rb')
    self.old_data = fileobj.read()
    fileobj.close()





  def tearDown(self):
    test_system_setup.TestCase.tearDown(self)
    shutil.rmtree(self.evil_dir)





  def test_replay_on_client(self):
    """
    <Purpose>
      Illustrate replay attack vulnerability.

    """

    # Client performs initial updates.
    if self.TUF:
      self.tuf_client_refresh_metadata()
      self.tuf_client_download_updates()
      targetpath1 = os.path.join(self.tuf_client_downloads_dir, 
                                 self.filename1)
      self.assertTrue(os.path.exists(targetpath1))
      current_file_data = self.read_file_content(targetpath1)
    else:
      current_file_data = self.client_download(self.filename1)

    # Content of the file at the repository.
    update_data_at_repo = self.read_file_content(self.filepath1)
    self.assertEquals(update_data_at_repo, current_file_data)

    # Developer updates 'filename1' update and updates the repository.
    new_data = 'NewData'
    self.add_or_change_file_at_repository(filename=self.filename1,
                                          data=new_data)
    if self.TUF:
      # If TUF is implemented, the developer needs to refresh tuf repository.
      self.refresh_tuf_repository()

    # Client downloads the updated file 'filename1'.
    if self.TUF:
      self.tuf_client_refresh_metadata()
      self.tuf_client_download_updates()
      current_file_data = self.read_file_content(targetpath1)
    else:
      current_file_data = self.client_download(self.filename1)
    
    self.assertEquals(new_data, current_file_data)

    # Attacker tries to be clever.
    rel_evil_dir = os.path.basename(self.evil_dir)
    self.url = 'http://localhost:'+str(self.port)+'/'+rel_evil_dir+'/'
    self.client_download(self.filename1)

    # Client downloads the updated file 'filename1' one more time.
    if self.TUF:
      self.tuf_client_refresh_metadata()
      self.tuf_client_download_updates()
      current_file_data = self.read_file_content(targetpath1)
    else:
      current_file_data = self.client_download(self.filename1)

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'new_data'.
    self.assertEquals(new_data, current_file_data, self.msg)





# Run unit test.
suite = unittest.TestLoader().loadTestsFromTestCase(TestReplayAttack)
unittest.TextTestRunner(verbosity=2).run(suite)