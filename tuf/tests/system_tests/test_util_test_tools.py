"""
<Program Name>
  test_util_test_tools.py

<Author>
  Konstantin Andrianov

<Started>
  February 26, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test util_test_tools.

"""
import os
import urllib
import unittest
import util_test_tools



class test_UtilTestTools(unittest.TestCase):
  def setUp(self):
    unittest.TestCase.setUp(self)
    self.temp_root, self.url = util_test_tools.init_repo(tuf=True)

  def tearDown(self):
    unittest.TestCase.tearDown(self)
    util_test_tools.cleanup()


#================================================#
#  Bellow are few quick tests to make sure that  #
#  everything works smoothly in util_test_tools. #
#================================================#

  # A few quick internal tests to see if everything runs smoothly.
  def test_direct_download(self):
    # Setup.
    downloads = os.path.join(self.temp_root, 'downloads')
    filepath = util_test_tools.add_file_to_repository('Test')
    file_basename = os.path.basename(filepath)
    url = self.url+'repo/'+file_basename
    downloaded_file = os.path.join(downloads, file_basename)

    # Test direct download using 'urllib.urlretrieve'.
    urllib.urlretrieve(url, downloaded_file)
    self.assertTrue(os.path.isfile(downloaded_file))

    # Verify the content of the downloaded file.
    downloaded_content = util_test_tools.read_file_content(downloaded_file)
    self.assertEquals('Test', downloaded_content)





  def test_correct_directory_structure(self):
    # Verify following directories exists: '{temp_root}/repo/',
    # '{temp_root}/downloads/.
    self.assertTrue(os.path.isdir(os.path.join(self.temp_root, 'repo')))
    self.assertTrue(os.path.isdir(os.path.join(self.temp_root, 'downloads')))

    # Verify that all necessary TUF-paths exist.
    tuf_repo = os.path.join(self.temp_root, 'tuf_repo')
    tuf_client = os.path.join(self.temp_root, 'tuf_client')
    metadata_dir = os.path.join(tuf_repo, 'metadata')
    current_dir = os.path.join(tuf_client, 'metadata', 'current')

    # Verify '{temp_root}/tuf_repo/metadata/role.txt' paths exists.
    for role in ['root', 'targets', 'release', 'timestamp']:
      # Repository side.
      role_file = os.path.join(metadata_dir, role+'.txt')
      self.assertTrue(os.path.isfile(role_file))

      # Client side.
      role_file = os.path.join(current_dir, role+'.txt')
      self.assertTrue(os.path.isfile(role_file))

    # Verify '{temp_root}/tuf_repo/keystore/keyid.key' exists.
    keys_list = os.listdir(os.path.join(tuf_repo, 'keystore'))
    self.assertEquals(len(keys_list), 1)

    # Verify '{temp_root}/tuf_repo/targets/' directory exists.
    self.assertTrue(os.path.isdir(os.path.join(tuf_repo, 'targets')))





  def test_methods(self):
    """
    Making sure following methods work as intended:
    - add_file_to_repository(data)
    - modify_file_at_repository(filepath, data)
    - delete_file_at_repository(filepath)
    - read_file_content(filepath)
    - tuf_refresh_repo()
    - tuf_refresh_and_download()

    Note: here file at the 'filepath' and the 'target' file at tuf-targets
    directory are identical files.
    Ex: filepath = '{temp_root}/repo/file.txt'
        target = '{temp_root}/tuf_repo/targets/file.txt'
    """

    repo = os.path.join(self.temp_root, 'repo')
    tuf_repo = os.path.join(self.temp_root, 'tuf_repo')
    downloads = os.path.join(self.temp_root, 'downloads')

    # Test 'add_file_to_repository(data)' and read_file_content(filepath)
    # methods
    filepath = util_test_tools.add_file_to_repository('Test')
    self.assertTrue(os.path.isfile(filepath))
    self.assertEquals(os.path.dirname(filepath), repo)
    filepath_content = util_test_tools.read_file_content(filepath)
    self.assertEquals('Test', filepath_content)

    # Test 'modify_file_at_repository(filepath, data)' method.
    filepath = util_test_tools.modify_file_at_repository(filepath, 'Modify')
    self.assertTrue(os.path.exists(filepath))
    filepath_content = util_test_tools.read_file_content(filepath)
    self.assertEquals('Modify', filepath_content)

    # Test 'tuf_refresh_repo' method.
    util_test_tools.tuf_refresh_repo()
    file_basename = os.path.basename(filepath)
    target = os.path.join(tuf_repo, 'targets', file_basename)
    self.assertTrue(os.path.isfile(target))

    # Test 'tuf_refresh_and_download()' method.
    util_test_tools.tuf_refresh_and_download()
    target = os.path.join(downloads, file_basename)
    self.assertTrue(os.path.isfile(target))

    # Test 'delete_file_at_repository(filepath)' method.
    util_test_tools.delete_file_at_repository(filepath)
    self.assertFalse(os.path.exists(filepath))

    # Test 'tuf_refresh_repo' method once more.
    util_test_tools.tuf_refresh_repo()
    file_basename = os.path.basename(filepath)
    target = os.path.join(tuf_repo, 'targets', file_basename)
    self.assertFalse(os.path.isfile(target))




if __name__ == '__main__':
  unittest.main()