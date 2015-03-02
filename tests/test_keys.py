#!/usr/bin/env python

"""
<Program Name>
  test_keys.py

<Author> 
  Vladimir Diaz

<Started>
  October 10, 2013. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_keys.py.
  TODO: test case for ed25519 key generation and refactor.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.keys

logger = logging.getLogger('tuf.test_keys')

KEYS = tuf.keys
FORMAT_ERROR_MSG = 'tuf.FormatError was raised! Check object\'s format.'
DATA = 'SOME DATA REQUIRING AUTHENTICITY.'



class TestKeys(unittest.TestCase):
  
  @classmethod 
  def setUpClass(cls):
    cls.rsakey_dict = KEYS.generate_rsa_key()
    cls.ed25519key_dict = KEYS.generate_ed25519_key()    


  def test_generate_rsa_key(self):
    _rsakey_dict = KEYS.generate_rsa_key()

    # Check if the format of the object returned by generate() corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(_rsakey_dict),
                     FORMAT_ERROR_MSG)

    # Passing a bit value that is <2048 to generate() - should raise 
    # 'tuf.FormatError'.
    self.assertRaises(tuf.FormatError, KEYS.generate_rsa_key, 555)

    # Passing a string instead of integer for a bit value.
    self.assertRaises(tuf.FormatError, KEYS.generate_rsa_key, 'bits')

    # NOTE if random bit value >=2048 (not 4096) is passed generate(bits) 
    # does not raise any errors and returns a valid key.
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(KEYS.generate_rsa_key(2048)))
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(KEYS.generate_rsa_key(4096)))



  def test_format_keyval_to_metadata(self):
    keyvalue = self.rsakey_dict['keyval']
    keytype = self.rsakey_dict['keytype']
    key_meta = KEYS.format_keyval_to_metadata(keytype, keyvalue)
    
    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None, 
                     tuf.formats.KEY_SCHEMA.check_match(key_meta), 
                     FORMAT_ERROR_MSG)    
    key_meta = KEYS.format_keyval_to_metadata(keytype, keyvalue, private=True)

    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None, tuf.formats.KEY_SCHEMA.check_match(key_meta), 
                     FORMAT_ERROR_MSG) 
    
    # Supplying a 'bad' keyvalue.
    self.assertRaises(tuf.FormatError, KEYS.format_keyval_to_metadata,
                      'bad_keytype', keyvalue)

    public = keyvalue['public']
    del keyvalue['public']
    self.assertRaises(tuf.FormatError, KEYS.format_keyval_to_metadata,
                      keytype, keyvalue)
    keyvalue['public'] = public
  
  
  
  def test_format_rsakey_from_pem(self):
    pem = self.rsakey_dict['keyval']['public']
    rsa_key = KEYS.format_rsakey_from_pem(pem)
    
    # Check if the format of the object returned by this function corresponds
    # to 'tuf.formats.RSAKEY_SCHEMA' format.
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(rsa_key)) 
    
    # Verify whitespace is stripped.
    self.assertEqual(rsa_key, KEYS.format_rsakey_from_pem(pem + '\n'))

    # Supplying a 'bad_pem' argument.
    self.assertRaises(tuf.FormatError, KEYS.format_rsakey_from_pem, 'bad_pem')

    # Supplying an improperly formatted PEM.
    # Strip the PEM header and footer.
    pem_header = '-----BEGIN PUBLIC KEY-----'
    self.assertRaises(tuf.FormatError, KEYS.format_rsakey_from_pem,
                      pem[len(pem_header):])
                      
    pem_footer = '-----END PUBLIC KEY-----'
    self.assertRaises(tuf.FormatError, KEYS.format_rsakey_from_pem,
                      pem[:-len(pem_footer)])



  def test_format_metadata_to_key(self):
    # Reconfiguring rsakey_dict to conform to KEY_SCHEMA
    # i.e. {keytype: 'rsa', keyval: {public: pub_key, private: priv_key}}
    keyid = self.rsakey_dict['keyid']
    del self.rsakey_dict['keyid']

    rsakey_dict_from_meta = KEYS.format_metadata_to_key(self.rsakey_dict) 

    # Check if the format of the object returned by this function corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None, 
           tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict_from_meta),
           FORMAT_ERROR_MSG)
    self.rsakey_dict['keyid'] = keyid
    
    # Supplying a wrong number of arguments.
    self.assertRaises(TypeError, KEYS.format_metadata_to_key)
    args = (self.rsakey_dict, self.rsakey_dict)
    self.assertRaises(TypeError, KEYS.format_metadata_to_key, *args)

    # Supplying a malformed argument to the function - should get FormatError
    keyval = self.rsakey_dict['keyval']  
    del self.rsakey_dict['keyval']
    self.assertRaises(tuf.FormatError, KEYS.format_metadata_to_key,
                      self.rsakey_dict)   
    self.rsakey_dict['keyval'] = keyval



  def test_helper_get_keyid(self):
    keytype = self.rsakey_dict['keytype'] 
    keyvalue = self.rsakey_dict['keyval']
    
    # Check format of 'keytype'.
    self.assertEqual(None, tuf.formats.KEYTYPE_SCHEMA.check_match(keytype),
                     FORMAT_ERROR_MSG)
    
    # Check format of 'keyvalue'.
    self.assertEqual(None, tuf.formats.KEYVAL_SCHEMA.check_match(keyvalue),
                     FORMAT_ERROR_MSG)

    keyid = KEYS._get_keyid(keytype, keyvalue)    

    # Check format of 'keyid' - the output of '_get_keyid()' function.
    self.assertEqual(None, tuf.formats.KEYID_SCHEMA.check_match(keyid),
                     FORMAT_ERROR_MSG)


  def test_create_signature(self):
    # Creating a signature for 'DATA'.
    rsa_signature = KEYS.create_signature(self.rsakey_dict, DATA)
    ed25519_signature = KEYS.create_signature(self.ed25519key_dict, DATA) 
    
    # Check format of output.
    self.assertEqual(None, 
                     tuf.formats.SIGNATURE_SCHEMA.check_match(rsa_signature),
                     FORMAT_ERROR_MSG)
    self.assertEqual(None, 
                     tuf.formats.SIGNATURE_SCHEMA.check_match(ed25519_signature),
                     FORMAT_ERROR_MSG)

    # Removing private key from 'rsakey_dict' - should raise a TypeError.
    private = self.rsakey_dict['keyval']['private'] 
    self.rsakey_dict['keyval']['private'] = ''
    
    args = (self.rsakey_dict, DATA)
    self.assertRaises(TypeError, KEYS.create_signature, *args)

    # Supplying an incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.create_signature)
    self.rsakey_dict['keyval']['private'] = private



  def test_verify_signature(self):
    # Creating a signature of 'DATA' to be verified.
    rsa_signature = KEYS.create_signature(self.rsakey_dict, DATA)
    ed25519_signature = KEYS.create_signature(self.ed25519key_dict, DATA)

    # Verifying the 'signature' of 'DATA'.
    verified = KEYS.verify_signature(self.rsakey_dict, rsa_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")
    
    # Verifying the 'ed25519_signature' of 'DATA'.
    verified = KEYS.verify_signature(self.ed25519key_dict, ed25519_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Testing an invalid 'rsa_signature'. Same 'rsa_signature' is passed, with 
    # 'DATA' different than the original 'DATA' that was used 
    # in creating the 'rsa_signature'. Function should return 'False'.
    
    # Modifying 'DATA'.
    _DATA = '1111' + DATA + '1111'
  
    # Verifying the 'signature' of modified '_DATA'.
    verified = KEYS.verify_signature(self.rsakey_dict, rsa_signature, _DATA)
    self.assertFalse(verified, 
                     'Returned \'True\' on an incorrect signature.')

    # Modifying 'signature' to pass an incorrect method since only
    # 'PyCrypto-PKCS#1 PSS' is accepted.
    rsa_signature['method'] = 'Biff'

    args = (self.rsakey_dict, rsa_signature, DATA)
    self.assertRaises(tuf.UnknownMethodError, KEYS.verify_signature, *args) 

    # Passing incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.verify_signature)
 
    # Verify that the pure python 'ed25519' base case (triggered if 'pynacl' is
    # unavailable) is executed in tuf.keys.verify_signature().
    KEYS._ED25519_CRYPTO_LIBRARY = 'invalid'
    KEYS._available_crypto_libraries = ['invalid']
    verified = KEYS.verify_signature(self.ed25519key_dict, ed25519_signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")
   
    # Reset to the expected available crypto libraries.
    KEYS._ED25519_CRYPTO_LIBRARY = 'pynacl'
    KEYS._available_crypto_libraries = ['ed25519', 'pycrypto', 'pynacl']
 

  
  def test_create_rsa_encrypted_pem(self):
    # Test valid arguments.
    private = self.rsakey_dict['keyval']['private']
    passphrase = 'secret'
    encrypted_pem = KEYS.create_rsa_encrypted_pem(private, passphrase)
    self.assertTrue(tuf.formats.PEMRSA_SCHEMA.matches(encrypted_pem))

    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, KEYS.create_rsa_encrypted_pem,
                      8, passphrase)
    
    self.assertRaises(tuf.FormatError, KEYS.create_rsa_encrypted_pem,
                      private, 8)

    # Test for missing required library.
    KEYS._RSA_CRYPTO_LIBRARY = 'invalid'
    self.assertRaises(tuf.UnsupportedLibraryError, KEYS.create_rsa_encrypted_pem,
                      private, passphrase)
    KEYS._RSA_CRYPTO_LIBRARY = 'pycrypto'
  
  
  
  def test_decrypt_key(self):
    # Test valid arguments.
    passphrase = 'secret'
    encrypted_key = KEYS.encrypt_key(self.rsakey_dict, passphrase).encode('utf-8')
    decrypted_key = KEYS.decrypt_key(encrypted_key, passphrase)

    self.assertTrue(tuf.formats.ANYKEY_SCHEMA.matches(decrypted_key))
    
    # Test improperly formatted arguments.
    self.assertRaises(tuf.FormatError, KEYS.decrypt_key,
                      8, passphrase)
    
    self.assertRaises(tuf.FormatError, KEYS.decrypt_key,
                      encrypted_key, 8)

    # Test for missing required library.
    KEYS._GENERAL_CRYPTO_LIBRARY = 'invalid'
    self.assertRaises(tuf.UnsupportedLibraryError, KEYS.decrypt_key,
                      encrypted_key, passphrase)
    KEYS._GENERAL_CRYPTO_LIBRARY = 'pycrypto' 



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
