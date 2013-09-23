"""
<Program Name>
  test_keystore.py

<Author>
  Konstantin Andrianov

<Started>
  April 27, 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for keystore.py.

"""

import unittest
import shutil
import os
import logging
import Crypto.Random
import Crypto.Protocol.KDF

import tuf
import tuf.repo.keystore
import tuf.rsa_key
import tuf.formats
import tuf.util
import tuf.log

logger = logging.getLogger('tuf.test_keystore')

# We'll need json module for testing '_encrypt()' and '_decrypt()'
# internal function.
json = tuf.util.import_json()

tuf.repo.keystore._PBKDF2_ITERATIONS = 1000

# Creating a directory string in current directory. 
_CURRENT_DIR = os.getcwd()
_DIR = os.path.join(_CURRENT_DIR, 'test_keystore')

# Check if directory '_DIR' exists.
if os.path.exists(_DIR):
  msg = ('\''+_DIR+'\' directory already exists,'+ 
        ' please change '+'\'_DIR\''+' to something else.')
  raise tuf.Error(msg)

KEYSTORE = tuf.repo.keystore
RSAKEYS = []
PASSWDS = []
temp_keys_info = []
temp_keys_vals = []

for i in range(3):
  # Populating the original 'RSAKEYS' and 'PASSWDS' lists.
  RSAKEYS.append(tuf.rsa_key.generate())
  PASSWDS.append('passwd_'+str(i))

  # Saving original copies of 'RSAKEYS' and 'PASSWDS' to temp variables
  # in order to repopulate them at the start of every test.
  temp_keys_info.append(RSAKEYS[i].values())
  temp_keys_vals.append(RSAKEYS[i]['keyval'].values())

temp_passwds=list(PASSWDS)



class TestKeystore(unittest.TestCase):
  def setUp(self):
    # Returning 'RSAKEY' and 'PASSWDS' to original state.
    for i in range(len(temp_keys_info)):
      RSAKEYS[i]['keytype'] = temp_keys_info[i][0]
      RSAKEYS[i]['keyid'] = temp_keys_info[i][1]
      RSAKEYS[i]['keyval'] = temp_keys_info[i][2]
      RSAKEYS[i]['keyval']['public'] = temp_keys_vals[i][0]
      RSAKEYS[i]['keyval']['private'] = temp_keys_vals[i][1]
      PASSWDS[i] = temp_passwds[i]



  def tearDown(self):
    # Empty keystore's databases.
    KEYSTORE.clear_keystore()

    # Check if directory '_DIR' exists, remove it if it does.
    if os.path.exists(_DIR):
      shutil.rmtree(_DIR)



  def test_clear_keystore(self):
    # Populate KEYSTORE's internal databases '_keystore' and '_derived_keys'.
    for i in range(3):
      KEYSTORE.add_rsakey(RSAKEYS[i], PASSWDS[i], RSAKEYS[i]['keyid'])
   
    # Verify KEYSTORE's internal databases ARE NOT EMPTY.
    self.assertTrue(len(KEYSTORE._keystore) > 0)
    self.assertTrue(len(KEYSTORE._derived_keys) > 0)
   
    # Clear KEYSTORE's internal databases.
    KEYSTORE.clear_keystore()

    # Verify KEYSTORE's internal databases ARE EMPTY.
    self.assertFalse(len(KEYSTORE._keystore) > 0)
    self.assertFalse(len(KEYSTORE._derived_keys) > 0)

  

  def test_add_rsakey(self):
    # Passing 2 arguments to the function and verifying that the internal 
    # databases have been modified.
    KEYSTORE.add_rsakey(RSAKEYS[0], PASSWDS[0])

    self.assertEqual(RSAKEYS[0], KEYSTORE._keystore[RSAKEYS[0]['keyid']], 
                     'Adding an rsa key dict was unsuccessful.')

    self.assertTrue(len(KEYSTORE._derived_keys) == 1,
              'Adding a password pertaining to \'_keyid\' was unsuccessful.')
    
    # Passing three arguments to the function, i.e. including the 'keyid'.
    KEYSTORE.add_rsakey(RSAKEYS[1], PASSWDS[1], RSAKEYS[1]['keyid'])

    self.assertEqual(RSAKEYS[1], 
                     KEYSTORE._keystore[RSAKEYS[1]['keyid']], 
                     'Adding an rsa key dict was unsuccessful.')

    self.assertTrue(len(KEYSTORE._derived_keys) == 2,
              'Adding a password pertaining to \'_keyid\' was unsuccessful.')

    # Passing a keyid that does not match the keyid in 'rsakey_dict'.
    _keyid = 'somedifferentkey123456789' 
    self.assertRaises(tuf.Error, KEYSTORE.add_rsakey, RSAKEYS[2], 
                      PASSWDS[2], _keyid)

    # Passing an existing 'rsakey_dict' object.
    self.assertRaises(tuf.KeyAlreadyExistsError, KEYSTORE.add_rsakey, 
                      RSAKEYS[1], PASSWDS[1], RSAKEYS[1]['keyid'])

    # Passing an 'rsakey_dict' that does not conform to the 'RSAKEY_SCHEMA'.
    del RSAKEYS[2]['keytype']
 
    self.assertRaises(tuf.FormatError, KEYSTORE.add_rsakey,
                      RSAKEYS[2], PASSWDS[2], RSAKEYS[2]['keyid'])



  def test_save_keystore_to_keyfiles(self):
    # Extract and store keyids in '_keyids' list.
    keyids = []

    # Populate KEYSTORE's internal databases '_keystore' and '_derived_keys'.
    for i in range(3):
      KEYSTORE.add_rsakey(RSAKEYS[i], PASSWDS[i], RSAKEYS[i]['keyid'])
      keyids.append(RSAKEYS[i]['keyid'])      

    # Check if directory '_DIR' exists, remove it if it does.
    if os.path.exists(_DIR):
      shutil.rmtree(_DIR)

    KEYSTORE.save_keystore_to_keyfiles(_DIR)
   
    # Check if directory '_DIR' has been created.
    self.assertTrue(os.path.exists(_DIR), 'Creating directory failed.')

    # Check if all of the key files where created and that they are not empty.
    for keyid in keyids:
      key_file = os.path.join(_DIR, str(keyid)+'.key')
      # Checks if key file has been created.
      self.assertTrue(os.path.exists(key_file), 'Key file does not exist.')

      file_stats = os.stat(key_file)
      # Checks if key file is not empty.
      self.assertTrue(file_stats.st_size > 0)

    # Passing an invalid 'directory_name' argument - an integer value.
    self.assertRaises(tuf.FormatError, KEYSTORE.save_keystore_to_keyfiles, 222)



  def test_load_keystore_from_keyfiles(self):
    keyids = []
    # Check if '_DIR' directory exists, if not - create it.
    if not os.path.exists(_DIR):
      # Populate KEYSTORE's internal databases.
      for i in range(3):
        KEYSTORE.add_rsakey(RSAKEYS[i], PASSWDS[i], RSAKEYS[i]['keyid'])
        keyids.append(RSAKEYS[i]['keyid'])

      # Create the key files.
      KEYSTORE.save_keystore_to_keyfiles(_DIR)
    
    # Clearing internal databases.
    KEYSTORE.clear_keystore()

    # Test normal conditions where two valid arguments are passed. 
    loaded_keys = KEYSTORE.load_keystore_from_keyfiles(_DIR, keyids, PASSWDS)
    
    # Loaded keys should all be contained in 'keyids'.
    loaded_keys_set = set(loaded_keys)
    keyids_set = set(keyids)
    intersect = keyids_set.intersection(loaded_keys_set)
    self.assertEquals(len(intersect), len(keyids))

    for i in range(3):
      self.assertEqual(RSAKEYS[i], KEYSTORE._keystore[RSAKEYS[i]['keyid']])

    # Clearing internal databases.
    KEYSTORE.clear_keystore()

    _invalid_dir = os.path.join(_CURRENT_DIR, 'invalid_directory')

    # Passing an invalid 'directory_name' argument - a directory that
    # does not exist. AS EXPECTED, THIS CALL SHOULDN'T RAISE ANY ERRORS.
    KEYSTORE.load_keystore_from_keyfiles(_invalid_dir, keyids, PASSWDS)

    # The keystore should not have loaded any keys.
    self.assertEqual(0, len(KEYSTORE._keystore))
    self.assertEqual(0, len(KEYSTORE._derived_keys))

    # Passing nonexistent 'keyids'.
    # AS EXPECTED, THIS CALL SHOULDN'T RAISE ANY ERRORS.
    invalid_keyids = ['333', '333', '333']
    KEYSTORE.load_keystore_from_keyfiles(_DIR, invalid_keyids, PASSWDS)
   
    # The keystore should not have loaded any keys.
    self.assertEqual(0, len(KEYSTORE._keystore))
    self.assertEqual(0, len(KEYSTORE._derived_keys))

    # Passing an invalid 'directory_name' argument - an integer value.
    self.assertRaises(tuf.FormatError, KEYSTORE.load_keystore_from_keyfiles,
                      333, keyids, PASSWDS)

    # Passing an invalid 'passwords' argument - a string value.
    self.assertRaises(tuf.FormatError, KEYSTORE.load_keystore_from_keyfiles,
                      _DIR, keyids, '333')

    # Passing an invalid 'passwords' argument - an integer value.
    self.assertRaises(tuf.FormatError, KEYSTORE.load_keystore_from_keyfiles,
                      _DIR, keyids, 333)

    # Passing an invalid 'keyids' argument - a string value.
    self.assertRaises(tuf.FormatError, KEYSTORE.load_keystore_from_keyfiles,
                      _DIR, '333', PASSWDS)
    
    # Passing an invalid 'keyids' argument - an integer value.
    self.assertRaises(tuf.FormatError, KEYSTORE.load_keystore_from_keyfiles,
                     _DIR, 333, PASSWDS)



  def test_change_password(self):
    # Populate KEYSTORE's internal databases.
    for i in range(2):
      KEYSTORE.add_rsakey(RSAKEYS[i], PASSWDS[i], RSAKEYS[i]['keyid'])

    derived_key_0 = KEYSTORE._derived_keys[RSAKEYS[0]['keyid']]
    # Create a new password.
    new_passwd = 'changed_password'

    # Change a password - normal case.
    KEYSTORE.change_password(RSAKEYS[0]['keyid'], PASSWDS[0], new_passwd)
    
    # Check if password was changed.
    new_derived_key = KEYSTORE._derived_keys[RSAKEYS[0]['keyid']]['derived_key']
    self.assertNotEqual(new_derived_key, 
                        derived_key_0['derived_key'])

    # Passing an invalid keyid (i.e., RSAKEY[2] that was not loaded into
    # the '_keystore').
    self.assertRaises(tuf.UnknownKeyError, KEYSTORE.change_password, 
                      RSAKEYS[2]['keyid'], PASSWDS[1], new_passwd)

    # Passing an incorrect old password.
    self.assertRaises(tuf.BadPasswordError, KEYSTORE.change_password,
                      RSAKEYS[1]['keyid'], PASSWDS[2], new_passwd)


   
  def test_get_key(self):
    # Populate KEYSTORE's internal databases.
    for i in range(2):
      KEYSTORE.add_rsakey(RSAKEYS[i], PASSWDS[i], RSAKEYS[i]['keyid'])

    # Get a key - normal case.
    self.assertEqual(KEYSTORE.get_key(RSAKEYS[0]['keyid']), RSAKEYS[0])    

    # Passing an invalid keyid.
    self.assertRaises(tuf.UnknownKeyError, 
                      KEYSTORE.get_key, RSAKEYS[2]['keyid'])
   
    # Passing an invalid keyid format.
    self.assertRaises(tuf.FormatError, KEYSTORE.get_key, 123)    



  def test_internal_encrypt(self):
    # Test for valid arguments to '_encrypt()' and a valid return type.
    salt = Crypto.Random.new().read(16)
    iterations = tuf.repo.keystore._PBKDF2_ITERATIONS
    derived_key = Crypto.Protocol.KDF.PBKDF2(PASSWDS[0], salt)
    derived_key_information = {'salt': salt, 'derived_key': derived_key,
                               'iterations': iterations}
    encrypted_key = KEYSTORE._encrypt(json.dumps(RSAKEYS[0]),
                                      derived_key_information)
    self.assertEqual(type(encrypted_key), str)
   
  
  
  def test_internal_decrypt(self):
    del RSAKEYS[0]['keyid']
    tuf.formats.KEY_SCHEMA.check_match(RSAKEYS[0])
    
    salt = Crypto.Random.new().read(16)
    salt, iterations, derived_key = \
      tuf.repo.keystore._generate_derived_key(PASSWDS[0], salt)
    derived_key_information = {'salt': salt,
                               'iterations': iterations,
                               'derived_key': derived_key}
    
    # Getting a valid encrypted key using '_encrypt()'.
    encrypted_key = KEYSTORE._encrypt(json.dumps(RSAKEYS[0]),
                                      derived_key_information)

    # Decrypting and decoding (using json's loads()) an encrypted file.
    #tuf.util.load_json_string(KEYSTORE._decrypt(encrypted_key, PASSWDS[0]))
    json.dumps(KEYSTORE._decrypt(encrypted_key, PASSWDS[0]))

    self.assertEqual(RSAKEYS[0], tuf.util.load_json_string(
                     KEYSTORE._decrypt(encrypted_key, PASSWDS[0])))
    
    # Passing an invalid password to try to decrypt the file.
    self.assertRaises(tuf.CryptoError, KEYSTORE._decrypt,
                      encrypted_key, PASSWDS[1])



def setUpModule():
  # setUpModule() is called before any test cases run.
  # Ensure the keystore has not been modified by a previous test, which may
  # affect assumptions (i.e., empty keystore) made by the tests cases in this
  # unit test.
  tuf.repo.keystore.clear_keystore()

def tearDownModule():
  # tearDownModule() is called after all the tests have run.
  # Ensure we clean up the keystore.  They say courtesy is contagious.
  tuf.repo.keystore.clear_keystore()


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
