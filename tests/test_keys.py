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


rsakey_dict = KEYS.generate_rsa_key()
temp_key_info_vals = rsakey_dict.values() 
temp_key_vals = rsakey_dict['keyval'].values()


class TestKeys(unittest.TestCase):
  def setUp(self):
    rsakey_dict['keytype']=temp_key_info_vals[0]
    rsakey_dict['keyid']=temp_key_info_vals[1]
    rsakey_dict['keyval']=temp_key_info_vals[2]
    rsakey_dict['keyval']['public']=temp_key_vals[0]
    rsakey_dict['keyval']['private']=temp_key_vals[1]


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
    keyvalue = rsakey_dict['keyval']
    keytype = rsakey_dict['keytype']
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

    del keyvalue['public']
    self.assertRaises(tuf.FormatError, KEYS.format_keyval_to_metadata,
                      keytype, keyvalue)


  def test_format_metadata_to_key(self):
    # Reconfiguring rsakey_dict to conform to KEY_SCHEMA
    # i.e. {keytype: 'rsa', keyval: {public: pub_key, private: priv_key}}
    #keyid = rsakey_dict['keyid']
    del rsakey_dict['keyid']

    rsakey_dict_from_meta = KEYS.format_metadata_to_key(rsakey_dict) 

    # Check if the format of the object returned by this function corresponds
    # to RSAKEY_SCHEMA format.
    self.assertEqual(None, 
           tuf.formats.RSAKEY_SCHEMA.check_match(rsakey_dict_from_meta),
           FORMAT_ERROR_MSG)

    # Supplying a wrong number of arguments.
    self.assertRaises(TypeError, KEYS.format_metadata_to_key)
    args = (rsakey_dict, rsakey_dict)
    self.assertRaises(TypeError, KEYS.format_metadata_to_key, *args)

    # Supplying a malformed argument to the function - should get FormatError
    del rsakey_dict['keyval']
    self.assertRaises(tuf.FormatError, KEYS.format_metadata_to_key,
                      rsakey_dict)   


  def test_helper_get_keyid(self):
    keytype = rsakey_dict['keytype'] 
    keyvalue = rsakey_dict['keyval']
    
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
    signature = KEYS.create_signature(rsakey_dict, DATA)
 
    # Check format of output.
    self.assertEqual(None, 
                     tuf.formats.SIGNATURE_SCHEMA.check_match(signature),
                     FORMAT_ERROR_MSG)

    # Removing private key from 'rsakey_dict' - should raise a TypeError.
    rsakey_dict['keyval']['private'] = ''
    
    args = (rsakey_dict, DATA)
    self.assertRaises(TypeError, KEYS.create_signature, *args)

    # Supplying an incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.create_signature)


  def test_verify_signature(self):
    # Creating a signature 'signature' of 'DATA' to be verified.
    signature = KEYS.create_signature(rsakey_dict, DATA)

    # Verifying the 'signature' of 'DATA'.
    verified = KEYS.verify_signature(rsakey_dict, signature, DATA)
    self.assertTrue(verified, "Incorrect signature.")

    # Testing an invalid 'signature'. Same 'signature' is passed, with 
    # 'DATA' different than the original 'DATA' that was used 
    # in creating the 'signature'. Function should return 'False'.
    
    # Modifying 'DATA'.
    _DATA = '1111'+DATA+'1111'
  
    # Verifying the 'signature' of modified '_DATA'.
    verified = KEYS.verify_signature(rsakey_dict, signature, _DATA)
    self.assertFalse(verified, 
                     'Returned \'True\' on an incorrect signature.')

    # Modifying 'signature' to pass an incorrect method since only
    # 'PyCrypto-PKCS#1 PSS' 
    # is accepted.
    signature['method'] = 'Biff'

    args = (rsakey_dict, signature, DATA)
    self.assertRaises(tuf.UnknownMethodError, KEYS.verify_signature, *args) 

    # Passing incorrect number of arguments.
    self.assertRaises(TypeError, KEYS.verify_signature)



# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
