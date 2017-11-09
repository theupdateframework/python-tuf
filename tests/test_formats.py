#!/usr/bin/env python

"""
<Program Name>
  test_formats.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'formats.py'
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import datetime

import tuf
import tuf.formats

import securesystemslib
import six


class TestFormats(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass



  def test_schemas(self):
    # Test conditions for valid schemas.
    valid_schemas = {
      'ISO8601_DATETIME_SCHEMA': (securesystemslib.formats.ISO8601_DATETIME_SCHEMA,
                                  '1985-10-21T13:20:00Z'),

      'UNIX_TIMESTAMP_SCHEMA': (securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA, 499137720),

      'HASH_SCHEMA': (securesystemslib.formats.HASH_SCHEMA, 'A4582BCF323BCEF'),

      'HASHDICT_SCHEMA': (securesystemslib.formats.HASHDICT_SCHEMA,
                          {'sha256': 'A4582BCF323BCEF'}),

      'HEX_SCHEMA': (securesystemslib.formats.HEX_SCHEMA, 'A4582BCF323BCEF'),

      'KEYID_SCHEMA': (securesystemslib.formats.KEYID_SCHEMA, '123456789abcdef'),

      'KEYIDS_SCHEMA': (securesystemslib.formats.KEYIDS_SCHEMA,
                        ['123456789abcdef', '123456789abcdef']),

      'SCHEME_SCHEMA': (securesystemslib.formats.SCHEME_SCHEMA, 'rsassa-pss-sha256'),

      'RELPATH_SCHEMA': (securesystemslib.formats.RELPATH_SCHEMA, 'metadata/root/'),

      'RELPATHS_SCHEMA': (securesystemslib.formats.RELPATHS_SCHEMA,
                          ['targets/role1/', 'targets/role2/']),

      'PATH_SCHEMA': (securesystemslib.formats.PATH_SCHEMA, '/home/someuser/'),

      'PATHS_SCHEMA': (securesystemslib.formats.PATHS_SCHEMA,
                       ['/home/McFly/', '/home/Tannen/']),

      'URL_SCHEMA': (securesystemslib.formats.URL_SCHEMA,
                     'https://www.updateframework.com/'),

      'VERSION_SCHEMA': (securesystemslib.formats.VERSION_SCHEMA,
                         {'major': 1, 'minor': 0, 'fix': 8}),

      'LENGTH_SCHEMA': (securesystemslib.formats.LENGTH_SCHEMA, 8),

      'NAME_SCHEMA': (securesystemslib.formats.NAME_SCHEMA, 'Marty McFly'),

      'BOOLEAN_SCHEMA': (securesystemslib.formats.BOOLEAN_SCHEMA, True),

      'THRESHOLD_SCHEMA': (securesystemslib.formats.THRESHOLD_SCHEMA, 1),

      'ROLENAME_SCHEMA': (tuf.formats.ROLENAME_SCHEMA, 'Root'),

      'RSAKEYBITS_SCHEMA': (securesystemslib.formats.RSAKEYBITS_SCHEMA, 4096),

      'PASSWORD_SCHEMA': (securesystemslib.formats.PASSWORD_SCHEMA, 'secret'),

      'PASSWORDS_SCHEMA': (securesystemslib.formats.PASSWORDS_SCHEMA, ['pass1', 'pass2']),

      'KEYVAL_SCHEMA': (securesystemslib.formats.KEYVAL_SCHEMA,
                        {'public': 'pubkey', 'private': 'privkey'}),

      'KEY_SCHEMA': (securesystemslib.formats.KEY_SCHEMA,
                     {'keytype': 'rsa',
                      'scheme': 'rsassa-pss-sha256',
                      'keyval': {'public': 'pubkey',
                                 'private': 'privkey'}}),

      'RSAKEY_SCHEMA': (securesystemslib.formats.RSAKEY_SCHEMA,
                        {'keytype': 'rsa',
                         'scheme': 'rsassa-pss-sha256',
                         'keyid': '123456789abcdef',
                         'keyval': {'public': 'pubkey',
                                    'private': 'privkey'}}),

      'FILEINFO_SCHEMA': (tuf.formats.FILEINFO_SCHEMA,
                          {'length': 1024,
                           'hashes': {'sha256': 'A4582BCF323BCEF'},
                           'custom': {'type': 'paintjob'}}),

      'FILEDICT_SCHEMA': (tuf.formats.FILEDICT_SCHEMA,
                          {'metadata/root.json': {'length': 1024,
                                                 'hashes': {'sha256': 'ABCD123'},
                                                 'custom': {'type': 'metadata'}}}),

      'TARGETINFO_SCHEMA': (tuf.formats.TARGETINFO_SCHEMA,
                            {'filepath': 'targets/target1.gif',
                             'fileinfo': {'length': 1024,
                                          'hashes': {'sha256': 'ABCD123'},
                                          'custom': {'type': 'target'}}}),

      'TARGETINFOS_SCHEMA': (tuf.formats.TARGETINFOS_SCHEMA,
                             [{'filepath': 'targets/target1.gif',
                               'fileinfo': {'length': 1024,
                                            'hashes': {'sha256': 'ABCD123'},
                                            'custom': {'type': 'target'}}}]),

      'SIGNATURE_SCHEMA': (securesystemslib.formats.SIGNATURE_SCHEMA,
                           {'keyid': '123abc',
                            'sig': 'A4582BCF323BCEF'}),

      'SIGNATURESTATUS_SCHEMA': (securesystemslib.formats.SIGNATURESTATUS_SCHEMA,
                                 {'threshold': 1,
                                  'good_sigs': ['123abc'],
                                  'bad_sigs': ['123abc'],
                                  'unknown_sigs': ['123abc'],
                                  'untrusted_sigs': ['123abc'],
                                  'unknown_signing_schemes': ['123abc']}),

      'SIGNABLE_SCHEMA': (tuf.formats.SIGNABLE_SCHEMA,
                          {'signed': 'signer',
                           'signatures': [{'keyid': '123abc',
                                           'sig': 'A4582BCF323BCEF'}]}),

      'KEYDICT_SCHEMA': (securesystemslib.formats.KEYDICT_SCHEMA,
                         {'123abc': {'keytype': 'rsa',
                                     'scheme': 'rsassa-pss-sha256',
                                     'keyval': {'public': 'pubkey',
                                                'private': 'privkey'}}}),

      'KEYDB_SCHEMA': (securesystemslib.formats.KEYDB_SCHEMA,
                       {'123abc': {'keytype': 'rsa',
                                   'scheme': 'rsassa-pss-sha256',
                                   'keyid': '123456789abcdef',
                                   'keyval': {'public': 'pubkey',
                                              'private': 'privkey'}}}),

      'SCPCONFIG_SCHEMA': (tuf.formats.SCPCONFIG_SCHEMA,
                           {'general': {'transfer_module': 'scp',
                                        'metadata_path': '/path/meta.json',
                                        'targets_directory': '/targets'},
                            'scp': {'host': 'http://localhost:8001',
                                    'user': 'McFly',
                                    'identity_file': '/home/.ssh/file',
                                    'remote_directory': '/home/McFly'}}),

      'RECEIVECONFIG_SCHEMA': (tuf.formats.RECEIVECONFIG_SCHEMA,
                               {'general': {'transfer_module': 'scp',
                                            'pushroots': ['/pushes'],
                                            'repository_directory': '/repo',
                                            'metadata_directory': '/repo/meta',
                                            'targets_directory': '/repo/targets',
                                            'backup_directory': '/repo/backup'}}),

      'ROLE_SCHEMA': (tuf.formats.ROLE_SCHEMA,
                      {'keyids': ['123abc'],
                       'threshold': 1,
                       'paths': ['path1/', 'path2']}),

      'ROLEDICT_SCHEMA': (tuf.formats.ROLEDICT_SCHEMA,
                          {'root': {'keyids': ['123abc'],
                           'threshold': 1,
                           'paths': ['path1/', 'path2']}}),

      'ROOT_SCHEMA': (tuf.formats.ROOT_SCHEMA,
                      {'_type': 'root',
                       'spec_version': '1.0',
                       'version': 8,
                       'consistent_snapshot': False,
                       'expires': '1985-10-21T13:20:00Z',
                       'keys': {'123abc': {'keytype': 'rsa',
                                           'scheme': 'rsassa-pss-sha256',
                                           'keyval': {'public': 'pubkey',
                                                      'private': 'privkey'}}},
                       'roles': {'root': {'keyids': ['123abc'],
                                          'threshold': 1,
                                          'paths': ['path1/', 'path2']}}}),

      'TARGETS_SCHEMA': (tuf.formats.TARGETS_SCHEMA,
        {'_type': 'targets',
         'spec_version': '1.0',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'targets': {'metadata/targets.json': {'length': 1024,
                                              'hashes': {'sha256': 'ABCD123'},
                                              'custom': {'type': 'metadata'}}},
         'delegations': {'keys': {'123abc': {'keytype':'rsa',
                                             'scheme': 'rsassa-pss-sha256',
                                             'keyval': {'public': 'pubkey',
                                                        'private': 'privkey'}}},
                         'roles': [{'name': 'root', 'keyids': ['123abc'],
                                    'threshold': 1,
                                    'paths': ['path1/', 'path2']}]}}),

      'SNAPSHOT_SCHEMA': (tuf.formats.SNAPSHOT_SCHEMA,
        {'_type': 'snapshot',
         'spec_version': '1.0',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'snapshot.json': {'version': 1024}}}),

      'TIMESTAMP_SCHEMA': (tuf.formats.TIMESTAMP_SCHEMA,
        {'_type': 'timestamp',
         'spec_version': '1.0',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'metadattimestamp.json': {'length': 1024,
                                            'hashes': {'sha256': 'AB1245'}}}}),

      'MIRROR_SCHEMA': (tuf.formats.MIRROR_SCHEMA,
        {'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}),

      'MIRRORDICT_SCHEMA': (tuf.formats.MIRRORDICT_SCHEMA,
        {'mirror1': {'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}}),

      'MIRRORLIST_SCHEMA': (tuf.formats.MIRRORLIST_SCHEMA,
        {'_type': 'mirrors',
         'version': 8,
         'spec_version': '1.0',
         'expires': '1985-10-21T13:20:00Z',
         'mirrors': [{'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}]})}

    # Iterate 'valid_schemas', ensuring each 'valid_schema' correctly matches
    # its respective 'schema_type'.
    for schema_name, (schema_type, valid_schema) in six.iteritems(valid_schemas):
      if not schema_type.matches(valid_schema):
        print('bad schema: ' + repr(valid_schema))
      self.assertEqual(True, schema_type.matches(valid_schema))

    # Test conditions for invalid schemas.
    # Set the 'valid_schema' of 'valid_schemas' to an invalid
    # value and test that it does not match 'schema_type'.
    for schema_name, (schema_type, valid_schema) in six.iteritems(valid_schemas):
      invalid_schema = 0xBAD
      if isinstance(schema_type, securesystemslib.schema.Integer):
        invalid_schema = 'BAD'
      self.assertEqual(False, schema_type.matches(invalid_schema))



  def test_MetaFile(self):
    # Test conditions for instantiations of a class that inherits from
    # 'tuf.formats.MetaFile'.
    class NewMetadataFile(tuf.formats.MetaFile):
      def __init__(self, version, expires):
        self.info = {}
        self.info['version'] = version
        self.info['expires'] = expires

    metadata = NewMetadataFile(123, 456)
    metadata2 = NewMetadataFile(123, 456)
    metadata3 = NewMetadataFile(333, 333)

    # Test the comparison operators.
    self.assertTrue(metadata == metadata2)
    self.assertFalse(metadata != metadata2)
    self.assertFalse(metadata == metadata3)

    # Test the 'getattr' method.
    self.assertEqual(123, getattr(metadata, 'version'))
    self.assertRaises(AttributeError, getattr, metadata, 'bad')



  def test_TimestampFile(self):
    # Test conditions for valid instances of 'tuf.formats.TimestampFile'.
    version = 8
    length = 88
    hashes = {'sha256': '3c7fe3eeded4a34'}
    expires = '1985-10-21T13:20:00Z'
    filedict = {'snapshot.json': {'length': length, 'hashes': hashes}}

    make_metadata = tuf.formats.TimestampFile.make_metadata
    from_metadata = tuf.formats.TimestampFile.from_metadata
    TIMESTAMP_SCHEMA = tuf.formats.TIMESTAMP_SCHEMA

    self.assertTrue(TIMESTAMP_SCHEMA.matches(make_metadata(version, expires,
                                                           filedict)))
    metadata = make_metadata(version, expires, filedict)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.TimestampFile))

    # Test conditions for invalid arguments.
    bad_version = 'eight'
    bad_expires = '2000'
    bad_filedict = 123
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, bad_version,
                                                      expires, filedict)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version,
                                                      bad_expires, filedict)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version,
                                                      expires, bad_filedict)

    self.assertRaises(securesystemslib.exceptions.FormatError, from_metadata, 123)





  def test_RootFile(self):
    # Test conditions for valid instances of 'tuf.formats.RootFile'.
    version = 8
    consistent_snapshot = False
    expires = '1985-10-21T13:20:00Z'

    keydict = {'123abc': {'keytype': 'rsa',
                          'scheme': 'rsassa-pss-sha256',
                          'keyval': {'public': 'pubkey',
                                     'private': 'privkey'}}}

    roledict = {'root': {'keyids': ['123abc'],
                         'threshold': 1,
                         'paths': ['path1/', 'path2']}}

    make_metadata = tuf.formats.RootFile.make_metadata
    from_metadata = tuf.formats.RootFile.from_metadata
    ROOT_SCHEMA = tuf.formats.ROOT_SCHEMA

    self.assertTrue(ROOT_SCHEMA.matches(make_metadata(version, expires,
        keydict, roledict, consistent_snapshot)))
    metadata = make_metadata(version, expires, keydict, roledict,
        consistent_snapshot)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.RootFile))

    # Test conditions for invalid arguments.
    bad_version = '8'
    bad_expires = 'eight'
    bad_keydict = 123
    bad_roledict = 123

    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata,
        bad_version, expires, keydict, roledict, consistent_snapshot)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata,
        version, bad_expires, keydict, roledict, consistent_snapshot)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata,
        version, expires, bad_keydict, roledict, consistent_snapshot)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata,
        version, expires, keydict, bad_roledict, consistent_snapshot)

    self.assertRaises(securesystemslib.exceptions.FormatError, from_metadata, 'bad')



  def test_SnapshotFile(self):
    # Test conditions for valid instances of 'tuf.formats.SnapshotFile'.
    version = 8
    expires = '1985-10-21T13:20:00Z'
    versiondict = {'targets.json' : {'version': version}}

    make_metadata = tuf.formats.SnapshotFile.make_metadata
    from_metadata = tuf.formats.SnapshotFile.from_metadata
    SNAPSHOT_SCHEMA = tuf.formats.SNAPSHOT_SCHEMA

    self.assertTrue(SNAPSHOT_SCHEMA.matches(make_metadata(version, expires,
                                                         versiondict)))
    metadata = make_metadata(version, expires, versiondict)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.SnapshotFile))

    # Test conditions for invalid arguments.
    bad_version = '8'
    bad_expires = '2000'
    bad_versiondict = 123
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version,
                                                      expires, bad_versiondict)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, bad_version, expires,
                                                      versiondict)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version, bad_expires,
                                                      bad_versiondict)

    self.assertRaises(securesystemslib.exceptions.FormatError, from_metadata, 123)



  def test_TargetsFile(self):
    # Test conditions for valid instances of 'tuf.formats.TargetsFile'.
    version = 8
    expires = '1985-10-21T13:20:00Z'

    filedict = {'metadata/targets.json': {'length': 1024,
                                         'hashes': {'sha256': 'ABCD123'},
                                         'custom': {'type': 'metadata'}}}

    delegations = {'keys': {'123abc': {'keytype':'rsa',
                                       'scheme': 'rsassa-pss-sha256',
                                       'keyval': {'public': 'pubkey',
                                                  'private': 'privkey'}}},
                   'roles': [{'name': 'root', 'keyids': ['123abc'],
                              'threshold': 1, 'paths': ['path1/', 'path2']}]}

    make_metadata = tuf.formats.TargetsFile.make_metadata
    from_metadata = tuf.formats.TargetsFile.from_metadata
    TARGETS_SCHEMA = tuf.formats.TARGETS_SCHEMA

    self.assertTrue(TARGETS_SCHEMA.matches(make_metadata(version, expires,
                                                         filedict, delegations)))
    self.assertTrue(TARGETS_SCHEMA.matches(make_metadata(version, expires, filedict)))

    metadata = make_metadata(version, expires, filedict, delegations)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.TargetsFile))

    # Test conditions for different combination of required arguments (i.e.,
    # a filedict or delegations argument is required.)
    metadata = make_metadata(version, expires, filedict)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.TargetsFile))

    metadata = make_metadata(version, expires, delegations=delegations)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.TargetsFile))

    # Directly instantiating a TargetsFile object.
    tuf.formats.TargetsFile(version, expires)
    tuf.formats.TargetsFile(version, expires, filedict)
    tuf.formats.TargetsFile(version, expires, delegations=delegations)

    # Test conditions for invalid arguments.
    bad_version = 'eight'
    bad_expires = '2000'
    bad_filedict = 123
    bad_delegations = 123
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, bad_version, expires,
                                                      filedict, delegations)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version, bad_expires,
                                                      filedict, delegations)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version, expires,
                                                      bad_filedict, delegations)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata, version, expires,
                                                      filedict, bad_delegations)
    self.assertRaises(securesystemslib.exceptions.Error, make_metadata, version, expires)

    self.assertRaises(securesystemslib.exceptions.FormatError, from_metadata, 123)



  def test_MirrorsFile(self):
    # Test normal case.
    version = 8
    expires = '1985-10-21T13:20:00Z'

    mirrors_file = tuf.formats.MirrorsFile(version, expires)

    make_metadata = tuf.formats.MirrorsFile.make_metadata
    from_metadata = tuf.formats.MirrorsFile.from_metadata

    self.assertRaises(NotImplementedError, make_metadata)
    self.assertRaises(NotImplementedError, from_metadata, mirrors_file)



  def test_unix_timestamp_to_datetime(self):
    # Test conditions for valid arguments.
    UNIX_TIMESTAMP_SCHEMA = securesystemslib.formats.UNIX_TIMESTAMP_SCHEMA
    self.assertTrue(datetime.datetime, tuf.formats.unix_timestamp_to_datetime(499137720))
    datetime_object = datetime.datetime(1985, 10, 26, 1, 22)
    self.assertEqual(datetime_object, tuf.formats.unix_timestamp_to_datetime(499137720))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.unix_timestamp_to_datetime, 'bad')
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.unix_timestamp_to_datetime, 1000000000000000000000)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.unix_timestamp_to_datetime, -1)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.unix_timestamp_to_datetime, ['5'])



  def test_datetime_to_unix_timestamp(self):
    # Test conditions for valid arguments.
    datetime_object = datetime.datetime(2015, 10, 21, 19, 28)
    self.assertEqual(1445455680, tuf.formats.datetime_to_unix_timestamp(datetime_object))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.datetime_to_unix_timestamp, 'bad')
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.datetime_to_unix_timestamp, 1000000000000000000000)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.datetime_to_unix_timestamp, ['1'])



  def test_format_base64(self):
    # Test conditions for valid arguments.
    data = 'updateframework'.encode('utf-8')
    self.assertEqual('dXBkYXRlZnJhbWV3b3Jr', tuf.formats.format_base64(data))
    self.assertTrue(isinstance(tuf.formats.format_base64(data), six.string_types))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.format_base64, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.format_base64, True)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.format_base64, ['123'])


  def test_parse_base64(self):
    # Test conditions for valid arguments.
    base64 = 'dXBkYXRlZnJhbWV3b3Jr'
    self.assertEqual(b'updateframework', tuf.formats.parse_base64(base64))
    self.assertTrue(isinstance(tuf.formats.parse_base64(base64), six.binary_type))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.parse_base64, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.parse_base64, True)
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.parse_base64, ['123'])
    self.assertRaises(securesystemslib.exceptions.FormatError, tuf.formats.parse_base64, '/')



  def test_make_signable(self):
    # Test conditions for expected make_signable() behavior.
    root = {'_type': 'root',
            'spec_version': '1.0',
            'version': 8,
            'consistent_snapshot': False,
            'expires': '1985-10-21T13:20:00Z',
            'keys': {'123abc': {'keytype': 'rsa',
                                'scheme': 'rsassa-pss-sha256',
                                'keyval': {'public': 'pubkey',
                                           'private': 'privkey'}}},
            'roles': {'root': {'keyids': ['123abc'],
                               'threshold': 1,
                               'paths': ['path1/', 'path2']}}}

    SIGNABLE_SCHEMA = tuf.formats.SIGNABLE_SCHEMA
    self.assertTrue(SIGNABLE_SCHEMA.matches(tuf.formats.make_signable(root)))
    signable = tuf.formats.make_signable(root)
    self.assertEqual('root', tuf.formats.check_signable_object_format(signable))

    self.assertEqual(signable, tuf.formats.make_signable(signable))

    # Test conditions for miscellaneous arguments.
    self.assertTrue(SIGNABLE_SCHEMA.matches(tuf.formats.make_signable('123')))
    self.assertTrue(SIGNABLE_SCHEMA.matches(tuf.formats.make_signable(123)))





  def test_make_fileinfo(self):
    # Test conditions for valid arguments.
    length = 1024
    hashes = {'sha256': 'A4582BCF323BCEF', 'sha512': 'A4582BCF323BFEF'}
    version = 8
    custom = {'type': 'paintjob'}

    FILEINFO_SCHEMA = tuf.formats.FILEINFO_SCHEMA
    make_fileinfo = tuf.formats.make_fileinfo
    self.assertTrue(FILEINFO_SCHEMA.matches(make_fileinfo(length, hashes, version, custom)))
    self.assertTrue(FILEINFO_SCHEMA.matches(make_fileinfo(length, hashes)))

    # Test conditions for invalid arguments.
    bad_length = 'bad'
    bad_hashes = 'bad'
    bad_custom = 'bad'

    self.assertRaises(securesystemslib.exceptions.FormatError, make_fileinfo, bad_length, hashes, custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_fileinfo, length, bad_hashes, custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_fileinfo, length, hashes, bad_custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_fileinfo, bad_length, hashes)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_fileinfo, length, bad_hashes)



  def test_make_versioninfo(self):
    # Test conditions for valid arguments.
    version_number = 8
    versioninfo = {'version': version_number}

    VERSIONINFO_SCHEMA = securesystemslib.formats.VERSIONINFO_SCHEMA
    make_versioninfo = tuf.formats.make_versioninfo
    self.assertTrue(VERSIONINFO_SCHEMA.matches(make_versioninfo(version_number)))

    # Test conditions for invalid arguments.
    bad_version_number = '8'

    self.assertRaises(securesystemslib.exceptions.FormatError, make_versioninfo, bad_version_number)



  def test_make_role_metadata(self):
    # Test conditions for valid arguments.
    keyids = ['123abc', 'abc123']
    threshold = 2
    paths = ['path1/', 'path2']
    path_hash_prefixes = ['000', '003']
    name = '123'

    ROLE_SCHEMA = tuf.formats.ROLE_SCHEMA
    make_role = tuf.formats.make_role_metadata

    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, name=name)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, paths=paths)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, name=name, paths=paths)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, name=name,
                                        path_hash_prefixes=path_hash_prefixes)))

    # Test conditions for invalid arguments.
    bad_keyids = 'bad'
    bad_threshold = 'bad'
    bad_paths = 'bad'
    bad_name = 123

    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, bad_keyids, threshold)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, bad_threshold)

    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, bad_keyids, threshold, paths=paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, bad_threshold, paths=paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, threshold, paths=bad_paths)

    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, bad_keyids, threshold, name=name)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, bad_threshold, name=name)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, threshold, name=bad_name)

    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, bad_keyids, threshold, name=name, paths=paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, bad_threshold, name=name, paths=paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, threshold, name=bad_name, paths=paths)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, threshold, name=name, paths=bad_paths)

    # 'paths' and 'path_hash_prefixes' cannot both be specified.
    self.assertRaises(securesystemslib.exceptions.FormatError, make_role, keyids, threshold, name, paths, path_hash_prefixes)

  def test_get_role_class(self):
    # Test conditions for valid arguments.
    get_role_class = tuf.formats.get_role_class

    self.assertEqual(tuf.formats.RootFile, get_role_class('Root'))
    self.assertEqual(tuf.formats.TargetsFile, get_role_class('Targets'))
    self.assertEqual(tuf.formats.SnapshotFile, get_role_class('Snapshot'))
    self.assertEqual(tuf.formats.TimestampFile, get_role_class('Timestamp'))
    self.assertEqual(tuf.formats.MirrorsFile, get_role_class('Mirrors'))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, get_role_class, 'role')
    self.assertRaises(securesystemslib.exceptions.FormatError, get_role_class, 'ROLE')
    self.assertRaises(securesystemslib.exceptions.FormatError, get_role_class, 'abcd')
    self.assertRaises(securesystemslib.exceptions.FormatError, get_role_class, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, get_role_class, tuf.formats.RootFile)



  def test_expected_meta_rolename(self):
    # Test conditions for valid arguments.
    expected_rolename = tuf.formats.expected_meta_rolename

    self.assertEqual('root', expected_rolename('Root'))
    self.assertEqual('targets', expected_rolename('Targets'))
    self.assertEqual('snapshot', expected_rolename('Snapshot'))
    self.assertEqual('timestamp', expected_rolename('Timestamp'))
    self.assertEqual('mirrors', expected_rolename('Mirrors'))
    self.assertEqual('targets role', expected_rolename('Targets Role'))
    self.assertEqual('root', expected_rolename('Root'))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, expected_rolename, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, expected_rolename, tuf.formats.RootFile)
    self.assertRaises(securesystemslib.exceptions.FormatError, expected_rolename, True)



  def test_check_signable_object_format(self):
    # Test condition for a valid argument.
    root = {'_type': 'root',
            'spec_version': '1.0',
            'version': 8,
            'consistent_snapshot': False,
            'expires': '1985-10-21T13:20:00Z',
            'keys': {'123abc': {'keytype': 'rsa',
                                'scheme': 'rsassa-pss-sha256',
                                'keyval': {'public': 'pubkey',
                                           'private': 'privkey'}}},
            'roles': {'root': {'keyids': ['123abc'],
                               'threshold': 1,
                               'paths': ['path1/', 'path2']}}}

    root = tuf.formats.make_signable(root)
    self.assertEqual('root', tuf.formats.check_signable_object_format(root))

    # Test conditions for invalid arguments.
    check_signable = tuf.formats.check_signable_object_format
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, 'root')
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, 123)
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, tuf.formats.RootFile)
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, True)

    saved_type = root['signed']['_type']
    del root['signed']['_type']
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, root)
    root['signed']['_type'] = saved_type

    root['signed']['_type'] = 'Root'
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, root)
    root['signed']['_type'] = 'root'

    del root['signed']['expires']
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, root)



  def test_encode_canonical(self):
    # Test conditions for valid arguments.
    encode = securesystemslib.formats.encode_canonical
    result = []
    output = result.append
    bad_output = 123

    self.assertEqual('""', encode(""))
    self.assertEqual('[1,2,3]', encode([1, 2, 3]))
    self.assertEqual('[1,2,3]', encode([1,2,3]))
    self.assertEqual('[]', encode([]))
    self.assertEqual('{"A":[99]}', encode({"A": [99]}))
    self.assertEqual('{"x":3,"y":2}', encode({"x": 3, "y": 2}))

    self.assertEqual('{"x":3,"y":null}', encode({"x": 3, "y": None}))

    # Condition where 'encode()' sends the result to the callable
    # 'output'.
    self.assertEqual(None, encode([1, 2, 3], output))
    self.assertEqual('[1,2,3]', ''.join(result))

    # Test conditions for invalid arguments.
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, tuf.formats.RootFile)
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0)
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": 8.0})
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0, output)

    self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": securesystemslib.exceptions.FormatError})


# Run unit test.
if __name__ == '__main__':
  unittest.main()
