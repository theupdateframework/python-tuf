"""
<Program Name>
  test_rollback_attack.py

<Author>
  Konstantin Andrianov

<Started>
  February 22, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Simulate a rollback attack.  A simple client update vs. client update 
  implementing TUF.

  Note: It's assumed that attacker does NOT have access to metadata signing
  keys.  Keep them safe!

  Note: There is no difference between 'updates' and 'target' files.

<Usage>
  To implement TUF use one of the following options: '-t', '--tuf', '--TUF'
  Ex. $python test_rollback_attack.py --tuf

  To simply run the a client update without implementing TUF omit the options.
  Ex. $python test_rollback_attack.py
"""

import os
import shutil
import test_system_setup
import unittest
import tempfile
import optparse


# Was the option set?
test_system_setup.tuf_option()


class TestRollbackAttack(test_system_setup.TestCase):
  # Whenever attack succeeds print following message:
  msg = 'Rollback attack succeeded!\n'


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





  @unittest.skipIf(test_system_setup.TestCase.TUF is True, 'Implemented TUF!')
  @unittest.expectedFailure
  def test_rollback_on_client(self):
    """
    <Purpose>
      Illustrate rollback attack vulnerability.

    """

    # Client performs initial updates.
    old_filename1_data = self.client_download(self.filename1)

    # Developer updates 'filename1' update and updates the repository.
    new_data = 'NewData'
    self.add_or_change_file_at_repository(filename=self.filename1,
                                          data=new_data)

    # Client downloads the updated file 'filename1'.
    new_filename_data = self.client_download(self.filename1)
    self.assertEquals(new_data, new_filename_data)

    # At this point the client is happy.  However, an evil tyrant has prepared
    # a little surprise.
    rel_evil_dir = os.path.basename(self.evil_dir)
    self.url = 'http://localhost:'+str(self.port)+'/'+rel_evil_dir+'/'
    self.client_download(self.filename1)

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'new_data'.
    self.assertEquals(new_data, self.client_download(self.filename1), self.msg)





  @unittest.skipIf(test_system_setup.TestCase.TUF is False,
                   'TUF was NOT implemented!')
  def test_rollback_using_tuf(self):
    """
    <Purpose>
      Illustrate protection against rollback attacks.

    """

    # TUF client initial update.
    self.tuf_client_download()
    targetpath1 = os.path.join(self.tuf_client_downloads_dir, self.filename1)
    self.assertTrue(os.path.exists(targetpath1))

    tuf_client_file_content = self.read_file_content(targetpath1)
      
    # Developer updates 'filename1' update and updates the TUF repository.
    new_data = 'NewData'
    self.add_or_change_file_at_repository(filename=self.filename1,
                                          data=new_data)
    self.refresh_tuf_repository()

    # TUF client performs another update.
    self.tuf_client_download()

    tuf_client_file_content = self.read_file_content(targetpath1)

    # Attacker tries to be clever.
    rel_evil_dir = os.path.basename(self.evil_dir)
    self.url = 'http://localhost:'+str(self.port)+'/'+rel_evil_dir+'/'
    
    # TUF client performs yet another update.
    self.tuf_client_download()

    # Check whether the attack succeeded by inspecting the content of the
    # update.  The update should contain 'new_data'.
    tuf_client_file_content = self.read_file_content(targetpath1)
    self.assertEquals(new_data, tuf_client_file_content, self.msg)





# Run unit test.
suite = unittest.TestLoader().loadTestsFromTestCase(TestRollbackAttack)
unittest.TextTestRunner(verbosity=2).run(suite)