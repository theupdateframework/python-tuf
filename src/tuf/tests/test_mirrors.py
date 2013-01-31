"""
<Program>
  test_mirrors.py

<Author>
  Konstantin Andrianov

<Started>
  March 26, 2012

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test mirrors.py module.

"""

import tuf
import tuf.formats as formats
import tuf.mirrors as mirrors
import copy
import unittest

# Unit tests
class TestMirrors(unittest.TestCase):
  mirrors = {'mirror1': {'url_prefix' : 'http://mirror1.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_paths' : ['targets/target1.py',
                                                    'targets/target2.py']},
             'mirror2': {'url_prefix' : 'http://mirror2.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_paths' : ['targets/target3.py',
                                                    'targets/target4.py']},
             'mirror3': {'url_prefix' : 'http://mirror3.com',
                         'metadata_path' : 'metadata',
                         'targets_path' : 'targets',
                         'confined_target_paths' : ['targets/target1.py',
                                                    'targets/target2.py']}}



  # Testing if wrong formats are being detected.
  def testFormatErrors(self):

    # Checking if all the formats are correct.
    self.assertTrue(formats.MIRRORDICT_SCHEMA.matches(TestMirrors.mirrors))


    file_path = 1234
    file_type = 'meta'
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      file_type, file_path, self.mirrors)

    file_path = []
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      file_type, file_path, TestMirrors.mirrors)

    file_path = {}
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      file_type, file_path, TestMirrors.mirrors)

    file_type = 1234
    file_path = 'meta2.txt'
    self.assertRaises(tuf.FormatError, mirrors.get_list_of_mirrors,
                      file_type, file_path, TestMirrors.mirrors)

    file_type = 'blah'
    self.assertEqual(mirrors.get_list_of_mirrors(file_type, file_path,
                                                 TestMirrors.mirrors),
                                                 [])


  """
  def testNormalCases(self):
    file_path = 'root.txt'
    file_type = 'meta'
    result = mirrors.get_list_of_mirrors(file_type, file_path,
                                             TestMirrors.mirrors)
    print result
    expected_output = ['http://mirror1.com/metadata/root.txt',
              'http://mirror2.com/metadata/root.txt',
              'http://mirror3.com/metadata/root.txt']
    self.assertEqual(expected_output, result, 'Expected output did not match')


    file_path = 'target1.py'
    file_type = 'target'
    result = mirrors.get_list_of_mirrors(file_type, file_path,
                                             TestMirrors.mirrors)
    print result
    expected_output = ['http://mirror1.com/targets/target1.py',
              'http://mirror3.com/targets/target1.py']
    self.assertEqual(expected_output, result, 'Expected output did not match')


    file_path = 'target4.py'
    file_type = 'targets'
    result = mirrors.get_list_of_mirrors(file_type, file_path,
                                             TestMirrors.mirrors)
    print result
    expected_output = ['http://mirror2.com/targets/target4.py']
    self.assertEqual(expected_output, result, 'Expected output did not match')
  """

  """
  def testNonExistingPath(self):
    file_path = 'tArgetz.py'
    file_type = 'target'
    empty_list = mirrors.get_list_of_mirrors(file_type,
                                             file_path,
                                             self.mirrors)
    msg = 'List returned on wrong \'file_path\' '+'should be empty.'
    self.assertEqual([],empty_list, msg)
  """


# Run the unittests
suite = unittest.TestLoader().loadTestsFromTestCase(TestMirrors)
unittest.TextTestRunner(verbosity=2).run(suite)
