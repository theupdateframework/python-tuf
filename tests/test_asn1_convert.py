#!/usr/bin/env python

"""
<Program>
  test_asn1_convert.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Unit tests for 'asn1_convert.py' and the lower-level ASN.1 encoding modules.

  NOTE: Run test_asn1_convert.py from the 'tuf/tests/' directory so that the
  module finds the test data and scripts.
"""

# Support some Python3 functionality in Python2:
#    Support print as a function (`print(x)`).
#    Do not use implicit relative imports.
#    Operator `/` performs float division, not floored division.
#    Interpret string literals as unicode. (Treat 'x' like u'x')
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

# Standard Library Imports
import unittest
import os
import logging
# Dependency Imports
import pyasn1
import pyasn1.type.univ as pyasn1_univ
import pyasn1.type.char as pyasn1_char
import pyasn1.codec.der.encoder as pyasn1_der_encoder
# TUF Imports
import tuf
import tuf.log
import tuf.unittest_toolbox as unittest_toolbox
import tuf.exceptions
import tuf.repository_tool as repo_tool
import tuf.encoding.asn1_convert as asn1_convert
import tuf.encoding.asn1_metadata_definitions as asn1_defs

logger = logging.getLogger('tuf.test_asn1_convert')

TEST_DATA_DIR = os.getcwd()

class TestASN1(unittest_toolbox.Modified_TestCase):
  def setUp(self):
    """
    """

    unittest_toolbox.Modified_TestCase.setUp(self)




  # Stop server process and perform clean up.
  def tearDown(self):
    unittest_toolbox.Modified_TestCase.tearDown(self)





  def baseline_convert_and_encode(self):
    """
    Fail if basic pyasn1 functionality is broken.
    """
    i = pyasn1_univ.Integer(5)
    self.assertEqual(5, i)

    i_der = pyasn1_der_encoder.encode(i)
    self.assertEqual(b'\x02\x01\x05', i_der)

    i_again = pyasn1_der_decoder.decode(i_der)
    self.assertEqual(i, i_again)





  def test_hex_string_octets_conversions(self):
    hex_string = '01234567890abcdef0'
    expected_der_of_octet_string = b'\x04\t\x01#Eg\x89\n\xbc\xde\xf0'

    octets_pyasn1 = asn1_convert.hex_str_to_pyasn1_octets(hex_string)
    self.assertEqual(
        hex_string, asn1_convert.hex_str_from_pyasn1_octets(octets_pyasn1))

    octets_der = asn1_convert.pyasn1_to_der(octets_pyasn1)
    self.assertEqual(expected_der_of_octet_string, octets_der)

    octets_pyasn1_again = asn1_convert.pyasn1_from_der(octets_der)
    self.assertEqual(octets_pyasn1.asNumbers(), octets_pyasn1_again.asNumbers())
    self.assertEqual(octets_pyasn1._value, octets_pyasn1_again._value)
    self.assertEqual(hex_string, asn1_convert.hex_str_from_pyasn1_octets(
        octets_pyasn1_again))





  def test_to_pyasn1_primitives(self):

    # Begin with basic objects: integers, strings, and octet strings.

    integer_pyasn1 = asn1_convert.to_pyasn1(
        123, pyasn1_univ.Integer)
    self.assertEqual(123, integer_pyasn1) # TODO: make sure this works enough like == for this purpose. If not, use assertTrue and ==
    self.assertIsInstance(integer_pyasn1, pyasn1_univ.Integer)

    string_pyasn1 = asn1_convert.to_pyasn1(
        'alphabeta', pyasn1_char.VisibleString)
    self.assertEqual('alphabeta', string_pyasn1)
    self.assertIsInstance(string_pyasn1, pyasn1_char.VisibleString)

    octets_pyasn1 = asn1_convert.to_pyasn1(
        '01234567890abcdef0', pyasn1_univ.OctetString)
    self.assertEqual(
        '01234567890abcdef0',
        asn1_convert.hex_str_from_pyasn1_octets(octets_pyasn1))
    self.assertIsInstance(octets_pyasn1, pyasn1_univ.OctetString)





  def test_to_pyasn1_sig(self):

    # Try a Signature object, more complex.
    sig = {'keyid': '12345', 'method': 'magical', 'value': 'abcdef1234567890'}
    sig_asn1 = asn1_convert.to_pyasn1(sig, asn1_defs.Signature)
    # TODO: Test the result of the signature conversion.





  def test_to_pyasn1_hashes(self):

    # Try a Hash object, of similar complexity as Signature.
    # First, produce it using the other functions, and compare it to the result
    # when produced by to_pyasn1.
    hash_type = 'sha256'
    hash_value = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_pyasn1_alt = asn1_convert.hash_to_pyasn1(hash_type, hash_value)
    hash_der_alt = asn1_convert.pyasn1_to_der(hash_pyasn1_alt)
    hash_pyasn1_again_alt = asn1_convert.pyasn1_from_der(hash_der_alt)

    h = {'function': hash_type, 'digest': hash_value}
    hash_pyasn1 = asn1_convert.to_pyasn1(h, asn1_defs.Hash)
    hash_der = asn1_convert.pyasn1_to_der(hash_pyasn1)
    hash_pyasn1_again = asn1_convert.pyasn1_from_der(hash_der)

    self.assertEqual(hash_pyasn1_alt, hash_pyasn1)
    self.assertEqual(hash_der_alt, hash_der)
    self.assertEqual(hash_pyasn1_again_alt, hash_pyasn1_again)
    self.assertEqual(hash_pyasn1, hash_pyasn1_again)


    # Try a Hashes object, more complex yet.
    # First, produce it using the other functions, and compare it to the result
    # when produced by to_pyasn1.
    hash_type1 = 'sha256'
    hash_value1 = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_type2 = 'sha512'
    hash_value2 = '1234567890abcdef0000000002173b903a5dff46b17b1bc3fe1e6ca0d0844f2f6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hashes_dict = {hash_type1: hash_value1, hash_type2: hash_value2}
    expected_der = b'1x0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/0J\x1a\x06sha512\x04@\x124Vx\x90\xab\xcd\xef\x00\x00\x00\x00\x02\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'


    hashes_pyasn1_alt = asn1_convert.hashes_to_pyasn1(hashes_dict)

    hashes_pyasn1 = asn1_convert.to_pyasn1(
        hashes_dict, asn1_defs.Hashes)

    # Repeat the same conversion. This catches some odd errors that I won't
    # explain here -- see the comments in asn1_convert.py pertaining to the
    # line that reads:
    #          sample_component_obj = type(datatype.componentType)()
    hashes_pyasn1 = asn1_convert.to_pyasn1(
        hashes_dict, asn1_defs.Hashes)

    # Both methods of generating Hashes objects should yield the same result.
    self.assertEqual(hashes_pyasn1_alt, hashes_pyasn1)

    hashes_der_alt = asn1_convert.pyasn1_to_der(hashes_pyasn1_alt)
    hashes_der = asn1_convert.pyasn1_to_der(hashes_pyasn1)

    self.assertEqual(expected_der, hashes_der_alt)
    self.assertEqual(expected_der, hashes_der)





  def test_to_pyasn1_keys(self):

    # Try key objects.

    # Import some public keys.
    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Convert them.
    ed_pub_pyasn1 = asn1_convert.to_pyasn1(ed_pub, asn1_defs.PublicKey)
    rsa_pub_pyasn1 = asn1_convert.to_pyasn1(rsa_pub, asn1_defs.PublicKey)









  def test_hash_to_pyasn1(self):
    # This doesn't use conversion_check because the hash_to_pyasn1 function
    # takes two arguments.
    hash_type = 'sha256'
    hash_value = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hash_pyasn1 = asn1_convert.hash_to_pyasn1(hash_type, hash_value)

    asn1_convert.pyasn1_to_der(hash_pyasn1)






  def test_hashes_to_pyasn1(self):

    hash_type1 = 'sha256'
    hash_value1 = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_type2 = 'sha512'
    hash_value2 = '1234567890abcdef0000000002173b903a5dff46b17b1bc3fe1e6ca0d0844f2f6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hashes_dict = {hash_type1: hash_value1, hash_type2: hash_value2}
    expected_der = b'1x0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/0J\x1a\x06sha512\x04@\x124Vx\x90\xab\xcd\xef\x00\x00\x00\x00\x02\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'

    hashes_pyasn1, hashes_der = self.conversion_check(
        hashes_dict, asn1_convert.hashes_to_pyasn1, expected_der=expected_der)

    self.assertEqual(len(hashes_dict), len(hashes_pyasn1))
    self.assertEqual(hash_type1, str(hashes_pyasn1[0]['function']))
    self.assertEqual(hash_type2, str(hashes_pyasn1[1]['function']))

    # These two are probably redundant, given conversion_check call above,
    # but they do test hex_str_from_pyasn1_octets.
    self.assertEqual(hash_value1,
        asn1_convert.hex_str_from_pyasn1_octets(hashes_pyasn1[0]['digest']))
    self.assertEqual(hash_value2,
        asn1_convert.hex_str_from_pyasn1_octets(hashes_pyasn1[1]['digest']))





  def test_public_key_to_pyasn1(self):

    # Import some keys.

    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Convert them.

    ed_pub_pyasn1 = asn1_convert.public_key_to_pyasn1(ed_pub)
    rsa_pub_pyasn1 = asn1_convert.public_key_to_pyasn1(rsa_pub)





  def conversion_check(self, data, func_to_asn1,
      func_from_asn1=None, expected_der=None):
    """
    By default:
     - Convert data to ASN.1 using func_to_asn1 argument.
     - Encode ASN.1 to DER.
     - Decode DER to ASN.1 again.
     - Return the ASN.1 and DER values produced in case the caller wants to use
       them to perform additional tests.

    Optionally:
     - Compare the provided expected DER data to what was produced.
     - Convert ASN.1 back to original using optional func_from_asn1 argument.
    """
    data_asn1 = func_to_asn1(data)
    data_der = asn1_convert.pyasn1_to_der(data_asn1)

    if expected_der is not None:
      self.assertEqual(expected_der, data_der)

    else:
      print('Original data: ' + str(data))
      print('DER data: ' + str(data_der))


    data_asn1_again = asn1_convert.pyasn1_from_der(data_der)
    self.assertEqual(data_asn1, data_asn1_again)

    if func_from_asn1 is not None:
      # Convert original->pyasn1 data back and test it.
      data_again = func_from_asn1(data_asn1)
      self.assertEqual(data, data_again)

      # Convert original->pyasn1->der data back and test it.
      data_again_again = func_from_asn1(data_asn1_again)
      self.assertEqual(data, data_again_again)

    # Also return the values produced in case there is additional testing that
    # is to be done, specific to the particular data.
    return data_asn1, data_der



# Run unit test.
if __name__ == '__main__':
  unittest.main()
