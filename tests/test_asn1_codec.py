import tuf
import tuf.util
import tuf.asn1_codec as asn1_codec
import tuf.conf
import tuf.repository_tool as repo_tool # to import a key for a signing attempt
import unittest
import sys # Python version
import os # getcwd()

tuf.conf.METADATA_FORMAT = 'json'

class TestASN1Conversion(unittest.TestCase):

  @classmethod
  def setUpClass(cls):

    private_key_fname = os.path.join(
        os.getcwd(), 'tests', 'repository_data', 'keystore', 'targets_key')

    cls.test_signing_key = repo_tool.import_ed25519_privatekey_from_file(
        private_key_fname, 'password')


  # THIS NEXT TEST fails because the TUF root.json test file in question here
  # uses an RSA key, which the ASN1 conversion does not yet support.
  # TODO: <~> FIX.
  # Our ASN1 conversion doesn't seem to support RSA keys. In particular, it is
  # being assumed that the key values are hex strings ('f9ac1325...') but an
  # RSA public key value is e.g. '-----BEGIN PUBLIC
  # KEY------\nMIIBojANBgk...\n...'
  @unittest.expectedFailure
  def test_1_root_partial_convert(self):
    # Test 1: only_signed conversion PyDict -> ASN1 BER of Root
    partial_der_conversion_tester(
        'tests/repository_data/repository/metadata/root.json', self)



  def test_2_tuf_sample_timestamp_partial_convert(self):
    """Test 2: only_signed conversion PyDict -> ASN1 BER of Timestamp"""
    partial_der_conversion_tester(
        'tests/repository_data/repository/metadata/timestamp.json', self)



  def test_3_snapshot_partial_convert(self):
    # Test 3: only_signed conversion PyDict -> ASN1 BER of Snapshot
    partial_der_conversion_tester(
        'tests/repository_data/repository/metadata/snapshot.json', self)



  def test_4_simple_targets_partial_convert(self):
    """Test 4: only_signed conversion PyDict -> ASN1 BER of simple Targets"""
    partial_der_conversion_tester(
        'tests/repository_data/targets_simpler.json', self)



  def test_5_delegated_partial_convert(self):
    """Test 5: only_signed conversion PyDict -> ASN1 BER of delegated role"""
    partial_der_conversion_tester(
        'tests/repository_data/repository/metadata/role1.json', self)



  # THIS NEXT TEST fails because the TUF targets.json test file used here
  # uses a custom parameter that the ASN1 conversion does not yet support,
  # specifically 'file_permissions'.
  # TODO: <~> FIX. In order to be TUF compliant, ASN.1 metadata has to be
  # able to take arbitrary custom key-value pairs.
  # Targets custom data can be arbitrary. The targetsmetadata.py converter does
  # not support that and has to. It'll need to treat everything it's given as a
  # string regardless of its type and covert it to ASN1 with the name
  # preserved, in a dict of some sort....
  @unittest.expectedFailure
  def test_6_targets_w_custom_partial_convert(self):
    """Test 5: only_signed conversion PyDict -> ASN1 BER of Targets"""
    partial_der_conversion_tester(
        'tests/repository_data/repository/metadata/targets.json', self)





  def test_11_root_uptane_partial_convert(self):
    """Test 11: only_signed conversion PyDict -> ASN1 BER of Root"""
    partial_der_conversion_tester(
        'tests/repository_data/uptane_mainrepo_root.json', self)
    partial_der_conversion_tester(
        'tests/repository_data/uptane_director_root.json', self)



  def test_12_snapshot_uptane_partial_convert(self):
    """Test 12: only_signed conversion PyDict -> ASN1 BER of Snapshot"""
    partial_der_conversion_tester(
        'tests/repository_data/uptane_mainrepo_snapshot.json', self)
    partial_der_conversion_tester(
        'tests/repository_data/uptane_director_snapshot.json', self)



  def test_13_timestamp_uptane_partial_convert(self):
    """Test 13: only_signed conversion PyDict -> ASN1 BER of Snapshot"""
    partial_der_conversion_tester(
        'tests/repository_data/uptane_mainrepo_snapshot.json', self)
    partial_der_conversion_tester(
        'tests/repository_data/uptane_director_snapshot.json', self)



  def test_14_targets_uptane_partial_convert(self):
    """Test 14: only_signed conversion PyDict -> ASN1 BER of Targets"""
    partial_der_conversion_tester(
        'tests/repository_data/uptane_mainrepo_targets.json', self)
    partial_der_conversion_tester(
        'tests/repository_data/uptane_director_targets.json', self)



  def test_15_delegated_uptane_partial_convert(self):
    """Test 15: only_signed conversion PyDict -> ASN1 BER of Snapshot"""
    partial_der_conversion_tester(
        'tests/repository_data/uptane_mainrepo_role1.json', self)
    # No delegations for the Director, so no second case to test.








def partial_der_conversion_tester(json_fname, cls): # Clunky.
  """
  This function takes as a second parameter the unittest.TestCase object whose
  functions (assertTrue etc) it can use. This is awkward and inappropriate. :P
  Find a different means of providing modularity instead of this one.
  (Can't just have this method in the class above because it would be run as
  a test. Could have default parameters and do that, but that's clunky, too.)
  """


  role_signable_pydict = tuf.util.load_file(json_fname)

  # Test each of the different kinds of conversions

  # Convert and return only the 'signed' portion, the metadata payload itself,
  # without including any signatures.
  cls.assertTrue(is_valid_nonempty_der(
      asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict, only_signed=True)))

  # Convert the full signable ('signed' and 'signatures'), maintaining the
  # existing signature in a new format and encoding.
  cls.assertTrue(is_valid_nonempty_der(
      asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict)))

  # # Convert the full signable ('signed' and 'signatures'), but discarding the
  # # original signatures and re-signing over, instead, the hash of the converted,
  # # ASN.1/DER 'signed' element.
  # cls.assertTrue(is_valid_nonempty_der(
  #     asn1_codec.convert_signed_metadata_to_der(
  #     role_signable_pydict, resign=True,
  #     private_key=self.test_signing_key)))





def is_valid_nonempty_der(der_string):
  """
  Currently a hacky test to see if the result is a non-empty byte string.

  This CAN raise false failures, stochastically, in Python2. In Python2,
  where bytes and str are the same type, we check to see if, anywhere in the
  string, there is a character requiring a \\x escape, as would almost
  certainly happen in an adequately long DER string of bytes. As a result,
  short or very regular strings may raise false failures in Python2.

  The best way to really do this test is to decode the DER and see if
  believable ASN.1 has come out of it.
  """
  if not der_string:
    return False
  elif sys.version_info.major < 3:
    return '\\x' in repr(der_string)
  else:
    return isinstance(der_string, bytes)





if __name__ == '__main__':
  unittest.main()

