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
import asn1crypto as asn1
import asn1crypto.core as asn1_core
'''
import pyasn1
import pyasn1.type.univ as pyasn1_univ
import pyasn1.type.char as pyasn1_char
import pyasn1.codec.der.encoder as pyasn1_der_encoder
'''
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




  def test_baseline(self):
    """
    Fail if basic asn1crypto functionality is broken.
    Use Integer and VisibleString.
    """

    i = asn1_core.Integer(5)
    self.assertEqual(5, i.native)

    i_der = i.dump()
    self.assertEqual(b'\x02\x01\x05', i_der)

    # Convert back and test.
    self.assertEqual(5, asn1_core.load(i_der).native)
    self.assertEqual(5, asn1_core.Integer.load(i_der).native)


    s = 'testword'
    expected_der_of_string = b'\x1a\x08testword'

    s_asn1 = asn1_core.VisibleString(s)
    self.assertEqual(s, s_asn1.native)

    s_der = s_asn1.dump()
    self.assertEqual(expected_der_of_string, s_der)

    self.assertEqual(s_asn1, asn1_core.load(s_der))
    self.assertEqual(s_asn1, asn1_core.VisibleString.load(s_der))

    self.assertEqual(s, asn1_core.load(s_der).native)
    self.assertEqual(s, asn1_core.VisibleString.load(s_der).native)




  '''

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





  def test_hex_string_octets_conversions_pyasn1(self):
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
    sig = {'keyid': '123456', 'method': 'magical', 'value': 'abcdef1234567890'}

    expected_der = \
        b'0\x18\x04\x03\x124V\x1a\x07magical\x04\x08\xab\xcd\xef\x124Vx\x90'

    """sig_asn1, sig_der = self.conversion_check_pyasn1("""
    self.conversion_check_pyasn1(
        sig,
        asn1_convert.to_pyasn1,
        from_asn1_func=asn1_convert.from_pyasn1,
        expected_der=expected_der,
        second_arg=asn1_defs.Signature)

    # Manual, without using conversion_check:

    # sig_asn1 = asn1_convert.to_pyasn1(sig, asn1_defs.Signature)
    # TODO: Test the result of the signature conversion.

    # sig_der = asn1_convert.pyasn1_to_der(sig_asn1)

    # print(sig_der)

    # sig_asn1_again = asn1_convert.pyasn1_from_der(sig_der)

    # self.assertEqual(sig_asn1, sig_asn1_again)
    # print('sig_asn1: ' + str(sig_asn1))
    # print('sig_asn1_again: ' + str(sig_asn1_again))

    # sig_again = asn1_convert.from_pyasn1(sig_asn1, asn1_defs.Signature)
    # sig_again_from_der = asn1_convert.from_pyasn1(sig_asn1_again, asn1_defs.Signature)

    # self.assertEqual(sig, sig_again)






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

    h_expected_der = \
        b'0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'

    self.conversion_check_pyasn1(
        h,
        asn1_convert.to_pyasn1,
        #from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=h_expected_der,
        second_arg=asn1_defs.Hash)


    # # Manual, without conversion_check:
    # hash_pyasn1 = asn1_convert.to_pyasn1(h, asn1_defs.Hash)
    # hash_der = asn1_convert.pyasn1_to_der(hash_pyasn1)
    # hash_pyasn1_again = asn1_convert.pyasn1_from_der(hash_der)

    # self.assertEqual(hash_pyasn1_alt, hash_pyasn1)
    # self.assertEqual(hash_der_alt, hash_der)
    # self.assertEqual(hash_pyasn1_again_alt, hash_pyasn1_again)
    # self.assertEqual(hash_pyasn1, hash_pyasn1_again)


    # Try a Hashes object, more complex yet.
    # First, produce it using the other functions, and compare it to the result
    # when produced by to_pyasn1.
    hash_type1 = 'sha256'
    hash_value1 = '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'
    hash_type2 = 'sha512'
    hash_value2 = '1234567890abcdef0000000002173b903a5dff46b17b1bc3fe1e6ca0d0844f2f6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    hashes_dict = {hash_type1: hash_value1, hash_type2: hash_value2}
    expected_der = b'1x0*\x1a\x06sha256\x04 i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/0J\x1a\x06sha512\x04@\x124Vx\x90\xab\xcd\xef\x00\x00\x00\x00\x02\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/i\x90\xb6Xn\xd5E8|jQ\xdbb\x17;\x90:]\xffF\xb1{\x1b\xc3\xfe\x1el\xa0\xd0\x84O/'


    # Test using the custom converter for hashes, hashes_to_pyasn1.
    hashes_asn1_alt, junk = self.conversion_check_pyasn1(
        hashes_dict,
        asn1_convert.hashes_to_pyasn1,
        #from_asn1_func=asn1_convert.hashes_from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK; func not yet written?
        expected_der=expected_der)

    # Test using the generic converter, to_pyasn1.
    hashes_asn1, junk = self.conversion_check_pyasn1(
        hashes_dict,
        asn1_convert.to_pyasn1,
        #from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=expected_der,
        second_arg=asn1_defs.Hashes)

    # Compare the two ASN.1 results (from specific and generic converters) to
    # each other.
    self.assertEqual(hashes_asn1_alt, hashes_asn1)



    # Test manually, without conversion_check

    # hashes_pyasn1_alt = asn1_convert.hashes_to_pyasn1(hashes_dict)

    # hashes_pyasn1 = asn1_convert.to_pyasn1(
    #     hashes_dict, asn1_defs.Hashes)

    # # Repeat the same conversion. This catches some odd errors that I won't
    # # explain here -- see the comments in asn1_convert.py pertaining to the
    # # line that reads:
    # #          sample_component_obj = type(datatype.componentType)()
    # hashes_pyasn1 = asn1_convert.to_pyasn1(
    #     hashes_dict, asn1_defs.Hashes)

    # # Both methods of generating Hashes objects should yield the same result.
    # self.assertEqual(hashes_pyasn1_alt, hashes_pyasn1)

    # hashes_der_alt = asn1_convert.pyasn1_to_der(hashes_pyasn1_alt)
    # hashes_der = asn1_convert.pyasn1_to_der(hashes_pyasn1)

    # self.assertEqual(expected_der, hashes_der_alt)
    # self.assertEqual(expected_der, hashes_der)





  def test_to_pyasn1_keys(self):

    # Import some public keys.
    ed_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'timestamp_key.pub')
    rsa_pub_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'root_key.pub')

    ed_pub = repo_tool.import_ed25519_publickey_from_file(ed_pub_fname)
    rsa_pub = repo_tool.import_rsa_publickey_from_file(rsa_pub_fname)

    # Expected DER results from converting the keys:
    ed_key_expected_der = \
        b'0&\x1a\x07ed25519\x1a\x07ed255191\x000\x10\x1a\x06sha256\x1a\x06sha512'
    rsa_key_expected_der = \
        b'0,\x1a\x03rsa\x1a\x11rsassa-pss-sha2561\x000\x10\x1a\x06sha256\x1a\x06sha512'


    # Convert them and test along the way.
    self.conversion_check_pyasn1(
        ed_pub,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=ed_key_expected_der,
        second_arg=asn1_defs.PublicKey)

    self.conversion_check_pyasn1(
        rsa_pub,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=rsa_key_expected_der,
        second_arg=asn1_defs.PublicKey)





  def test_to_pyasn1_timestamp_hash_of_snapshot(self):
    # First, try the HashOfSnapshot piece of the Timestamp data.

    # First, let's build the JSON-compatible metadata dict.
    snapshot_fname = 'snapshot.json'
    snapshot_hash_func = 'sha256'
    snapshot_hash_digest = \
        '6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f'

    # Construct the JSON-compatible, TUF-internal piece of hash metadata, as it
    # would exist inside timestamp.json.
    hashes_of_snapshot = {
        snapshot_fname: {'hashes': {snapshot_hash_func: snapshot_hash_digest}}}


    # Next, let's manually construct the HashOfSnapshot object, to see if the
    # converter gets it right.

    # First, construct the hashes. We'll just use one in this test.

    h = asn1_defs.Hash()
    h['function'] = snapshot_hash_func
    h['digest'] = pyasn1_univ.OctetString(hexValue=snapshot_hash_digest)

    hashes = asn1_defs.Hashes()
    hashes[0] = h

    # Note: HashesContainer is a vapid layer of the ASN.1 metadata which
    # exists to map to a similarly vapid layer of the JSON-compatible metadata.
    hashes_container = asn1_defs.HashesContainer()
    hashes_container['hashes'] = hashes


    expected_pyasn1 = asn1_defs.HashOfSnapshot()
    expected_pyasn1['filename'] = snapshot_fname
    # expected_pyasn1['num-hashes'] = len(snapshot_hash[snapshot_fname]['hashes'])
    expected_pyasn1['hashes'] = hashes_container

    expected_der = asn1_convert.pyasn1_to_der(expected_pyasn1)


    hashes_of_snapshot_pyasn1, hashes_of_snapshot_der = self.conversion_check_pyasn1(
        hashes_of_snapshot,
        asn1_convert.to_pyasn1,
        # from_asn1_func=asn1_convert.from_pyasn1,   # TODO: DO NOT SKIP CONVERTING BACK
        expected_der=expected_der,
        second_arg=asn1_defs.HashOfSnapshot)

    # In addition to testing the conversion and the expected DER, let's test
    # the expected ASN.1:
    self.assertEqual(expected_pyasn1, hashes_of_snapshot_pyasn1)





  # def test_to_pyasn1_timestamp(self):

  #   sample_timestamp = {
  #       "signatures": [
  #         {
  #           "keyid": "8a1c4a3ac2d515dec982ba9910c5fd79b91ae57f625b9cff25d06bf0a61c1758",
  #           "sig": "7dddbfe94d6d80253433551700ea6dfe4171a33f1227a07830e951900b8325d67c3dce6410b9cf55abefa3dfca0b57814a4965c2d6ee60bb0336755cd0557e03"
  #         }
  #       ],
  #       "signed": {
  #         "_type": "timestamp",
  #         "expires": "2030-01-01T00:00:00Z",
  #         "meta": {
  #           "snapshot.json": {
  #             "hashes": {
  #               "sha256": "6990b6586ed545387c6a51db62173b903a5dff46b17b1bc3fe1e6ca0d0844f2f"
  #             },
  #             "length": 554,
  #             "version": 1
  #           }
  #         },
  #         "spec_version": "1.0",
  #         "version": 1
  #       }}

  #   TimestampMetadata







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

    hashes_pyasn1, hashes_der = self.conversion_check_pyasn1(
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




  def conversion_check_pyasn1(self, data, to_asn1_func,
      from_asn1_func=None, expected_der=None, second_arg=None):
    """
    By default:
     - Convert data to ASN.1 using "to_asn1_func" argument.
     - Encode ASN.1 to DER.
     - Decode DER to ASN.1 again.
     - Test equality with originally-generated ASN.1. (Note that this uses
       pyasn1 equality checks, which don't necessarily compare data labels,
       just data.)
     - Return the ASN.1 and DER values produced in case the caller wants to use
       them to perform additional tests.

    Optionally:
     - Compare the provided expected DER data to what was produced.
     - Using optional from_asn1_func:
         - Convert [original -> ASN.1 -> original] and test.
         - Convert [original -> ASN.1 -> DER -> ASN.1 -> original] and test.
     - Passes the given "second_arg" to "func_to_asn1" and (if provided)
       "from_asn1_func" when calling. This is of use for general conversion
       functions that must be told which datatype to convert to/from (like
       "to_asn1" and "from_asn1").
    """
    if second_arg is not None:
      data_asn1 = to_asn1_func(data, second_arg)
    else:
      data_asn1 = to_asn1_func(data)

    data_der = asn1_convert.pyasn1_to_der(data_asn1)

    if expected_der is not None:
      self.assertEqual(expected_der, data_der)

    else:
      print('Original data: ' + str(data))
      print('DER data: ' + str(data_der))


    data_asn1_again = asn1_convert.pyasn1_from_der(data_der)
    self.assertEqual(data_asn1, data_asn1_again)

    if from_asn1_func is not None:
      # Convert original->pyasn1 data back and test it.
      if second_arg is not None:
        data_again = from_asn1_func(data_asn1, second_arg)
      else:
        data_again = from_asn1_func(data_asn1)
      self.assertEqual(data, data_again)

      # Convert original->pyasn1->der data back and test it.
      if second_arg is not None:
        data_again_again = from_asn1_func(data_asn1_again, second_arg)
      else:
        data_again_again = from_asn1_func(data_asn1_again)
      self.assertEqual(data, data_again_again)

    # Also return the values produced in case there is additional testing that
    # is to be done, specific to the particular data.
    return data_asn1, data_der


  '''

  def assert_asn1_obj_equivalent(self, obj1, obj2):
    """
    Fail the test that called this function if asn1crypto objects obj1 and obj2
    are not identical in all relevant respects:
      - .dump()      (DER encoding)
      - .native      (native Python values when converted back)
      - ._children   (child info)
      - ._contents   (similar to _children)
      - ._fields     (Sequence/Set member type)
      - ._child_spec (SequenceOf/SetOf member type)
    """
    self.assertEqual(obj1.dump(), obj2.dump())

    # Note that it's good to touch .native on both of these before conducting
    # the next tests so that lazily-updated fields like _children will be
    # populated.
    self.assertEqual(obj1.native, obj2.native)

    for field in ['_contents', '_children', '_child_spec', '_fields']:

      # Do not replace these checks with getattr(, , None) -- not the same.

      self.assertEqual(hasattr(obj1, field), hasattr(obj2, field))

      if hasattr(obj1, field):
        self.assertEqual(getattr(obj1, field), getattr(obj2, field))



# Run unit test.
if __name__ == '__main__':
  unittest.main()
