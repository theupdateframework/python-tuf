import tuf
import tuf.util
import tuf.asn1_codec as asn1_codec
import tuf.conf
import unittest
import sys # Python version

tuf.conf.METADATA_FORMAT = 'json'

class TestASN1Conversion(unittest.TestCase):


  # THIS NEXT TEST fails because the TUF root.json test file in question here
  # uses an RSA key, which the ASN1 conversion does not yet support.
  # TODO: <~> FIX.
  # Our ASN1 conversion doesn't seem to support RSA keys. In particular, it is
  # being assumed that the key values are hex strings ('f9ac1325...') but an
  # RSA public key value is e.g. '-----BEGIN PUBLIC
  # KEY------\nMIIBojANBgk...\n...'
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








def partial_der_conversion_tester(json_fname, self): # Clunky.
  """
  This function takes as a second parameter the unittest.TestCase object whose
  functions (assertTrue etc) it can use. This is awkward and inappropriate. :P
  Find a different means of providing modularity instead of this one.
  (Can't just have this method in the class above because it would be run as
  a test. Could have default parameters and do that, but that's clunky, too.)
  """


  role_signable_pydict = tuf.util.load_file(json_fname)

  self.assertTrue(is_valid_nonempty_der(
      asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict, only_signed=True)))





def is_valid_nonempty_der(der_string):
  """
  Currently a trivial test to see if the result is a non-empty byte string.
  """
  if not der_string:
    return False
  elif sys.version_info.major < 3:
    return repr(der_string[0])[1:3] == '\\x'
  else:
    return isinstance(der_string, bytes)


if __name__ == '__main__':
  unittest.main()

