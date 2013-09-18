"""
<Program Name>
  test_rsa_key.py

<Author> 
  Konstantin Andrianov

<Started>
  April 24, 2012. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for rsa_key.py.

<Notes> 
  I'm using 'global rsakey_dict' - there is no harm in doing so since 
  in order to modify the global variable in any method, python requires
  explicit indication to modify i.e. declaring 'global' in each method 
  that modifies the global variable 'rsakey_dict'. 

"""

import unittest
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.rsa_key

logger = logging.getLogger('tuf.test_rsa_key')

RSA_KEY = tuf.rsa_key
FORMAT_ERROR_MSG = 'tuf.FormatError was raised! Check object\'s format.'
DATA = 'SOME DATA REQUIRING AUTHENTICITY.'


rsakey_dict = RSA_KEY.generate()
temp_key_info_vals = rsakey_dict.values() 
temp_key_vals = rsakey_dict['keyval'].values()


class TestRsa_key(unittest.TestCase):
  def setUp(self):
    rsakey_dict['keytype']=temp_key_info_vals[0]
    rsakey_dict['keyid']=temp_key_info_vals[1]
    rsakey_dict['keyval']=temp_key_info_vals[2]
    rsakey_dict['keyval']['public']=temp_key_vals[0]
    rsakey_dict['keyval']['private']=temp_key_vals[1]

 
  def test_generate(self):
    _rsakey_dict = RSA_KEY.generate()

    # Check if the format of the object returned by generate() corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(_rsakey_dict),
                     FORMAT_ERROR_MSG)

    # Passing a bit value that is <2048 to generate() - should raise 
    # 'tuf.FormatError'.
    self.assertRaises(tuf.FormatError, RSA_KEY.generate, 555)

    # Passing a string instead of integer for a bit value.
    self.assertRaises(tuf.FormatError, RSA_KEY.generate, 'bits')

    # NOTE if random bit value >=2048 (not 4096) is passed generate(bits) 
    # does not raise any errors and returns a valid key.
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(RSA_KEY.generate(2048)))
    self.assertTrue(tuf.formats.RSAKEY_SCHEMA.matches(RSA_KEY.generate(4096)))
    
  def test_create_in_metadata_format(self):
    key_value = rsakey_dict['keyval']
    key_meta = RSA_KEY.create_in_metadata_format(key_value)
    
    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None, 
                     tuf.formats.KEY_SCHEMA.check_match(key_meta), 
                     FORMAT_ERROR_MSG)    
    key_meta = RSA_KEY.create_in_metadata_format(key_value, private=True)

    # Check if the format of the object returned by this function corresponds
    # to KEY_SCHEMA format.
    self.assertEqual(None, tuf.formats.KEY_SCHEMA.check_match(key_meta), 
                     FORMAT_ERROR_MSG) 

    # Supplying a 'bad' key_value.
    del key_value['public']
    self.assertRaises(tuf.FormatError, RSA_KEY.create_in_metadata_format,
                      key_value)


  def test_create_from_metadata_format(self):
    # Reconfiguring rsakey_dict to conform to KEY_SCHEMA
    # i.e. {keytype: 'rsa', keyval: {public: pub_key, private: priv_key}}
    #keyid = rsakey_dict['keyid']
    del rsakey_dict['keyid']

    rsakey_dict_from_meta = RSA_KEY.create_from_metadata_format(rsakey_dict) 

    # Check if the format of the object returned by this function corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None, 
           tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict_from_meta),
           FORMAT_ERROR_MSG)

    # Supplying a wrong number of arguments.
    self.assertRaises(TypeError, RSA_KEY.create_from_metadata_format)
    args = (rsakey_dict, rsakey_dict)
    self.assertRaises(TypeError, RSA_KEY.create_from_metadata_format, *args)

    # Supplying a malformed argument to the function - should get FormatError
    del rsakey_dict['keyval']
    self.assertRaises(tuf.FormatError, RSA_KEY.create_from_metadata_format,
                      rsakey_dict)   


  def test_helper_get_keyid(self):
    key_value = rsakey_dict['keyval']
    
    # Check format of 'key_value'.
    self.assertEqual(None, tuf.formats.KEYVAL_SCHEMA.check_match(key_value),
                     FORMAT_ERROR_MSG)

    keyid = RSA_KEY._get_keyid(key_value)    

    # Check format of 'keyid' - the output of '_get_keyid()' function.
    self.assertEqual(None, tuf.formats.KEYID_SCHEMA.check_match(keyid),
                     FORMAT_ERROR_MSG)


  def test_createsignature(self):
    # Creating a signature for 'DATA'.
    signature = RSA_KEY.create_signature(rsakey_dict, DATA)
 
    # Check format of output.
    self.assertEqual(None, 
                     tuf.formats.SIGNATURE_SCHEMA.check_match(signature),
                     FORMAT_ERROR_MSG)

    # Removing private key from 'rsakey_dict' - should raise a TypeError.
    rsakey_dict['keyval']['private'] = ''
    
    args = (rsakey_dict, DATA)
    self.assertRaises(TypeError, RSA_KEY.create_signature, *args)

    # Supplying an incorrect number of arguments.
    self.assertRaises(TypeError, RSA_KEY.create_signature)


  def test_verify_signature(self):
    # Creating a signature 'signature' of 'DATA' to be verified.
    signature = RSA_KEY.create_signature(rsakey_dict, DATA)

    # Verifying the 'signature' of 'DATA'.
    verified = RSA_KEY.verify_signature(rsakey_dict, signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Testing an invalid 'signature'. Same 'signature' is passed, with 
    # 'DATA' different than the original 'DATA' that was used 
    # in creating the 'signature'. Function should return 'False'.
    
    # Modifying 'DATA'.
    _DATA = '1111'+DATA+'1111'
  
    # Verifying the 'signature' of modified '_DATA'.
    verified = RSA_KEY.verify_signature(rsakey_dict, signature, _DATA)
    self.assertFalse(verified, 
                     'Returned \'True\' on an incorrect signature.')

    # Modifying 'signature' to pass an incorrect method since only
    # 'PyCrypto-PKCS#1 PSS' 
    # is accepted.
    signature['method'] = 'Biff'

    args = (rsakey_dict, signature, DATA)
    self.assertRaises(tuf.UnknownMethodError, RSA_KEY.verify_signature, *args) 

    # Passing incorrect number of arguments.
    self.assertRaises(TypeError,RSA_KEY.verify_signature)


  def test_create_encrypted_pem(self):
    passphrase = 'pw'

    # Check format of 'rsakey_dict'.
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict),
                     FORMAT_ERROR_MSG)
    
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Generate the encrypted PEM string of 'rsakey_dict'.
    pem_rsakey = tuf.rsa_key.create_encrypted_pem(rsakey_dict, passphrase)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      tuf.rsa_key.create_encrypted_pem, 'Biff', passphrase)
    self.assertRaises(tuf.FormatError,
                      tuf.rsa_key.create_encrypted_pem, rsakey_dict, ['pw'])
  
  
  
  def test_create_from_encrypted_pem(self):
    passphrase = 'pw'

    # Check format of 'rsakey_dict'.
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict),
                     FORMAT_ERROR_MSG)
    
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Generate the encrypted PEM string of 'rsakey_dict'.
    pem_rsakey = tuf.rsa_key.create_encrypted_pem(rsakey_dict, passphrase)

    # Decrypt 'pem_rsakey' and verify the decrypted object is properly
    # formatted.
    decrypted_rsakey = tuf.rsa_key.create_from_encrypted_pem(pem_rsakey,
                                                             passphrase)
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(decrypted_rsakey),
                     FORMAT_ERROR_MSG)

    # Does 'decrypted_rsakey' match the original 'rsakey_dict'.
    self.assertEqual(rsakey_dict, decrypted_rsakey)

    # Attempt decryption of 'pem_rsakey' using an incorrect passphrase.
    self.assertRaises(tuf.CryptoError,
                      tuf.rsa_key.create_from_encrypted_pem, pem_rsakey,
                                                             'bad_pw')
    # Check for non-encrypted PEM string.  create_from_encrypted_pem()/PyCrypto
    # returns a tuf.formats.RSAKEY_SCHEMA object if PEM formatted string is
    # not actually encrypted but still a valid PEM string.
    non_encrypted_private_key = rsakey_dict['keyval']['private']
    decrypted_non_encrypted = tuf.rsa_key.create_from_encrypted_pem(
                              non_encrypted_private_key, passphrase)
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(
                           decrypted_non_encrypted), FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      tuf.rsa_key.create_from_encrypted_pem, 123, passphrase)
    self.assertRaises(tuf.FormatError,
                      tuf.rsa_key.create_from_encrypted_pem, pem_rsakey, ['pw'])
    self.assertRaises(tuf.CryptoError,
                      tuf.rsa_key.create_from_encrypted_pem, 'invalid_pem',
                                                              passphrase)
 


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
