import os
import shutil
import test_system_setup
import unittest
import tempfile
import optparse


class TestRollbackAttack(test_system_setup.TestCase):
  # Whenever attack succeeds print following message:
  msg = 'Roleback attack succeeded!\n'

  @staticmethod
  def _tuf_option():
    usage = 'usage: %prog [options]'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-t', '--tuf', '--TUF', action='store_true', dest='tuf', 
                      default=False, help='Implement tuf.')
    option, args = parser.parse_args()
    return option.tuf

  TestRollbackAttack.TUF = _tuf_option()


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


  def test_rollback_on_client(self):
    # Client performs initial updates.
    old_filename1_data = self.client_download(self.filename1)

    # Developer updates 'filename1' update and updates the repository.
    new_data = 'NewData'
    self.add_or_change_file_at_repository(filename=self.filename1,
                                          data=new_data)

    # Client downloads the updated file 'filename1'.
    new_filename_data = self.client_download(self.filename1)

    # At this point the client is happy.  However, an evil tyrant is prepared
    # a little surprise.
    rel_evil_dir = os.path.basename(self.evil_dir)
    self.url = 'http://localhost:'+str(self.port)+'/'+rel_evil_dir+'/'
    self.client_download(self.filename1)

    # Check client's downloads directory, if indeed the client has an update
    # with the old content.
    self.assertEquals(new_data, self.client_download(self.filename1), self.msg)


  def test_rollback_using_tuf(self):
    if self.TUF = False:
      print 'TUF is NOT implement!\n'
      return

      






# Run unit test.
suite = unittest.TestLoader().loadTestsFromTestCase(TestRollbackAttack)
unittest.TextTestRunner(verbosity=2).run(suite)