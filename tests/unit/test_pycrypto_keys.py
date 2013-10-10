"""
<Program Name>
  test_pycrypto_keys.py

<Author> 
  Vladimir Diaz 

<Started>
  October 10, 2013. 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for test_pycrypto_keys.py.
"""

import unittest
import logging

import tuf
import tuf.log
import tuf.formats
import tuf.pycrypto_keys

logger = logging.getLogger('tuf.test_pycrypto_keys')

FORMAT_ERROR_MSG = 'tuf.FormatError raised.  Check object\'s format.'
public_rsa, private_rsa = tuf.pycrypto_keys.generate_rsa_public_and_private()


class TestPycrypto_keys(unittest.TestCase):
  def setUp(self):
    pass


  def test_generate_rsa_public_and_private(self):
    pass


  def test_create_signature(self):
    pass


  def test_verify_signature(self):
    pass


  def test_create_rsa_encrypted_pem(self):
    passphrase = 'pw'

    # Check format of 'public_rsa'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(public_rsa),
                     FORMAT_ERROR_MSG)
    
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Generate the encrypted PEM string of 'public_rsa'.
    pem_rsakey = tuf.pycrypto_keys.create_rsa_encrypted_pem(private_rsa, passphrase)

    # Check format of 'pem_rsakey'.
    self.assertEqual(None, tuf.formats.PEMRSA_SCHEMA.check_match(pem_rsakey),
                     FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      tuf.pycrypto_keys.create_rsa_encrypted_pem, 1, passphrase)
    self.assertRaises(tuf.FormatError,
                      tuf.pycrypto_keys.create_rsa_encrypted_pem, private_rsa, ['pw'])
  
  
  
  def test_create_rsa_public_and_private_from_encrypted_pem(self):
    passphrase = 'pw'

    # Generate the encrypted PEM string of 'public_rsa'.
    pem_rsakey = tuf.pycrypto_keys.create_rsa_encrypted_pem(private_rsa, passphrase)
   
    # Check format of 'passphrase'.
    self.assertEqual(None, tuf.formats.PASSWORD_SCHEMA.check_match(passphrase),
                     FORMAT_ERROR_MSG)

    # Decrypt 'pem_rsakey' and verify the decrypted object is properly
    # formatted.
    decrypted_rsakey = tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem(pem_rsakey,
                                                             passphrase)
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(decrypted_rsakey),
                     FORMAT_ERROR_MSG)

    # Does 'decrypted_rsakey' match the original 'rsakey_dict'.
    self.assertEqual(rsakey_dict, decrypted_rsakey)

    # Attempt decryption of 'pem_rsakey' using an incorrect passphrase.
    self.assertRaises(tuf.CryptoError,
                      tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem, pem_rsakey,
                                                             'bad_pw')
    # Check for non-encrypted PEM string.  create_rsa_public_and_private_from_encrypted_pem()/PyCrypto
    # returns a tuf.formats.RSAKEY_SCHEMA object if PEM formatted string is
    # not actually encrypted but still a valid PEM string.
    non_encrypted_private_key = rsakey_dict['keyval']['private']
    decrypted_non_encrypted = tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem(
                              non_encrypted_private_key, passphrase)
    self.assertEqual(None, tuf.formats.RSAKEY_SCHEMA.check_match(
                           decrypted_non_encrypted), FORMAT_ERROR_MSG)

    # Check for invalid arguments.
    self.assertRaises(tuf.FormatError,
                      tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem, 123, passphrase)
    self.assertRaises(tuf.FormatError,
                      tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem, pem_rsakey, ['pw'])
    self.assertRaises(tuf.CryptoError,
                      tuf.pycrypto_keys.create_rsa_public_and_private_from_encrypted_pem, 'invalid_pem',
                                                              passphrase)
 


# Run the unit tests.
if __name__ == '__main__':
  unittest.main()
