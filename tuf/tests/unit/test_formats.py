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

import unittest

import tuf
import tuf.formats
import tuf.schema



class TestFormats(unittest.TestCase):
  def setUp(self):
    pass



  def tearDown(self):
    pass



  def test_schemas(self):
    # Test conditions for valid schemas.
    valid_schemas = {
      'TIME_SCHEMA': (tuf.formats.TIME_SCHEMA, '2012-10-14 06:42:12 UTC'),
      
      'HASH_SCHEMA': (tuf.formats.HASH_SCHEMA, 'A4582BCF323BCEF'),
      
      'HASHDICT_SCHEMA': (tuf.formats.HASHDICT_SCHEMA,
                          {'sha256': 'A4582BCF323BCEF'}),
      
      'HEX_SCHEMA': (tuf.formats.HEX_SCHEMA, 'A4582BCF323BCEF'),
      
      'KEYID_SCHEMA': (tuf.formats.KEYID_SCHEMA, '123456789abcdef'),
      
      'KEYIDS_SCHEMA': (tuf.formats.KEYIDS_SCHEMA,
                        ['123456789abcdef', '123456789abcdef']),
      
      'SIG_METHOD_SCHEMA': (tuf.formats.SIG_METHOD_SCHEMA, 'evp'),
      
      'RELPATH_SCHEMA': (tuf.formats.RELPATH_SCHEMA, 'metadata/root/'),
      
      'RELPATHS_SCHEMA': (tuf.formats.RELPATHS_SCHEMA,
                          ['targets/role1/', 'targets/role2/']),
      
      'PATH_SCHEMA': (tuf.formats.PATH_SCHEMA, '/home/someuser/'),
      
      'PATHS_SCHEMA': (tuf.formats.PATHS_SCHEMA,
                       ['/home/McFly/', '/home/Tannen/']),
      
      'URL_SCHEMA': (tuf.formats.URL_SCHEMA,
                     'https://www.updateframework.com/'),
      
      'VERSION_SCHEMA': (tuf.formats.VERSION_SCHEMA,
                         {'major': 1, 'minor': 0, 'fix': 8}),
      
      'LENGTH_SCHEMA': (tuf.formats.LENGTH_SCHEMA, 8),
      
      'NAME_SCHEMA': (tuf.formats.NAME_SCHEMA, 'Marty McFly'),
      
      'TOGGLE_SCHEMA': (tuf.formats.TOGGLE_SCHEMA, True),
      
      'THRESHOLD_SCHEMA': (tuf.formats.THRESHOLD_SCHEMA, 1),
      
      'ROLENAME_SCHEMA': (tuf.formats.ROLENAME_SCHEMA, 'Root'),
      
      'RSAKEYBITS_SCHEMA': (tuf.formats.RSAKEYBITS_SCHEMA, 4096),
      
      'PASSWORD_SCHEMA': (tuf.formats.PASSWORD_SCHEMA, 'secret'),
      
      'PASSWORDS_SCHEMA': (tuf.formats.PASSWORDS_SCHEMA, ['pass1', 'pass2']),
      
      'KEYVAL_SCHEMA': (tuf.formats.KEYVAL_SCHEMA,
                        {'public': 'pubkey', 'private': 'privkey'}),
      
      'KEY_SCHEMA': (tuf.formats.KEY_SCHEMA,
                     {'keytype': 'rsa',
                      'keyval': {'public': 'pubkey',
                                 'private': 'privkey'}}),
      
      'RSAKEY_SCHEMA': (tuf.formats.RSAKEY_SCHEMA,
                        {'keytype': 'rsa',
                         'keyid': '123456789abcdef',
                         'keyval': {'public': 'pubkey',
                                    'private': 'privkey'}}),
      
      'FILEINFO_SCHEMA': (tuf.formats.FILEINFO_SCHEMA,
                          {'length': 1024,
                           'hashes': {'sha256': 'A4582BCF323BCEF'},
                           'custom': {'type': 'paintjob'}}),
      
      'FILEDICT_SCHEMA': (tuf.formats.FILEDICT_SCHEMA,
                          {'metadata/root.txt': {'length': 1024,
                                                 'hashes': {'sha256': 'ABCD123'},
                                                 'custom': {'type': 'metadata'}}}),
      
      'TARGETFILE_SCHEMA': (tuf.formats.TARGETFILE_SCHEMA,
                            {'filepath': 'targets/target1.gif',
                             'fileinfo': {'length': 1024,
                                          'hashes': {'sha256': 'ABCD123'},
                                          'custom': {'type': 'target'}}}),
      
      'TARGETFILES_SCHEMA': (tuf.formats.TARGETFILES_SCHEMA,
                             [{'filepath': 'targets/target1.gif',
                               'fileinfo': {'length': 1024,
                                            'hashes': {'sha256': 'ABCD123'},
                                            'custom': {'type': 'target'}}}]),
      
      'SIGNATURE_SCHEMA': (tuf.formats.SIGNATURE_SCHEMA,
                           {'keyid': '123abc',
                            'method': 'evp',
                            'sig': 'A4582BCF323BCEF'}),
      
      'SIGNATURESTATUS_SCHEMA': (tuf.formats.SIGNATURESTATUS_SCHEMA,
                                 {'threshold': 1,
                                  'good_sigs': ['123abc'],
                                  'bad_sigs': ['123abc'],
                                  'unknown_sigs': ['123abc'],
                                  'untrusted_sigs': ['123abc'],
                                  'unknown_method_sigs': ['123abc']}),
      
      'SIGNABLE_SCHEMA': (tuf.formats.SIGNABLE_SCHEMA,
                          {'signed': 'signer',
                           'signatures': [{'keyid': '123abc',
                                           'method': 'evp',
                                           'sig': 'A4582BCF323BCEF'}]}),
      
      'KEYDICT_SCHEMA': (tuf.formats.KEYDICT_SCHEMA,
                         {'123abc': {'keytype': 'rsa',
                                     'keyval': {'public': 'pubkey',
                                                'private': 'privkey'}}}),

      'KEYDB_SCHEMA': (tuf.formats.KEYDB_SCHEMA,
                       {'123abc': {'keytype': 'rsa',
                                   'keyid': '123456789abcdef',
                                   'keyval': {'public': 'pubkey',
                                              'private': 'privkey'}}}),
      
      'SCPCONFIG_SCHEMA': (tuf.formats.SCPCONFIG_SCHEMA,
                           {'general': {'transfer_module': 'scp',
                                        'metadata_path': '/path/meta.txt',
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
                      {'_type': 'Root',
                       'version': 8,
                       'expires': '2012-10-16 06:42:12 UTC',
                       'keys': {'123abc': {'keytype': 'rsa',
                                           'keyval': {'public': 'pubkey',
                                                      'private': 'privkey'}}},
                       'roles': {'root': {'keyids': ['123abc'],
                                          'threshold': 1,
                                          'paths': ['path1/', 'path2']}}}),

      'TARGETS_SCHEMA': (tuf.formats.TARGETS_SCHEMA,
        {'_type': 'Targets',
         'version': 8,
         'expires': '2012-10-16 06:42:12 UTC',
         'targets': {'metadata/targets.txt': {'length': 1024,
                                              'hashes': {'sha256': 'ABCD123'},
                                              'custom': {'type': 'metadata'}}},
         'delegations': {'keys': {'123abc': {'keytype':'rsa',
                                             'keyval': {'public': 'pubkey',
                                                        'private': 'privkey'}}},
                         'roles': [{'name': 'root', 'keyids': ['123abc'],
                                    'threshold': 1,
                                    'paths': ['path1/', 'path2']}]}}),

      'RELEASE_SCHEMA': (tuf.formats.RELEASE_SCHEMA,
        {'_type': 'Release',
         'version': 8,
         'expires': '2012-10-16 06:42:12 UTC',
         'meta': {'metadata/release.txt': {'length': 1024,
                                           'hashes': {'sha256': 'ABCD123'},
                                           'custom': {'type': 'metadata'}}}}),

      'TIMESTAMP_SCHEMA': (tuf.formats.TIMESTAMP_SCHEMA,
        {'_type': 'Timestamp',
         'version': 8,
         'expires': '2012-10-16 06:42:12 UTC',
         'meta': {'metadata/timestamp.txt': {'length': 1024,
                                  'hashes': {'sha256': 'ABCD123'},
                                  'custom': {'type': 'metadata'}}}}),

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
        {'_type': 'Mirrors',
         'version': 8,
         'expires': '2012-10-16 06:42:12 UTC',
         'mirrors': [{'url_prefix': 'http://localhost:8001',
         'metadata_path': 'metadata/',
         'targets_path': 'targets/',
         'confined_target_dirs': ['path1/', 'path2/'],
         'custom': {'type': 'mirror'}}]})}
   
    # Iterate through 'valid_schemas', ensuring each 'valid_schema' correctly
    # matches its respective 'schema_type'.
    for schema_name, (schema_type, valid_schema) in valid_schemas.items():
      self.assertEqual(True, schema_type.matches(valid_schema))
   
    # Test conditions for invalid schemas.
    # Set the 'valid_schema' of 'valid_schemas' to an invalid
    # value and test that it does not match 'schema_type'.
    for schema_name, (schema_type, valid_schema) in valid_schemas.items():
      invalid_schema = 0xBAD
      if isinstance(schema_type, tuf.schema.Integer): 
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
    expires = '2012-10-16 06:42:12 UTC'
    filedict = {'metadata/timestamp.txt': {'length': 1024,
                                           'hashes': {'sha256': 'ABCD123'},
                                           'custom': {'type': 'metadata'}}}

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
    self.assertRaises(tuf.FormatError, make_metadata, bad_version,
                                                      expires, filedict)
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      bad_expires, filedict)
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      expires, bad_filedict)
    
    self.assertRaises(tuf.FormatError, from_metadata, 123)




  def test_RootFile(self):
    # Test conditions for valid instances of 'tuf.formats.RootFile'.
    version = 8
    expiration_seconds = 691200
    keydict = {'123abc': {'keytype': 'rsa',
                          'keyval': {'public': 'pubkey',
                                     'private': 'privkey'}}}

    roledict = {'root': {'keyids': ['123abc'],
                         'threshold': 1,
                         'paths': ['path1/', 'path2']}}

    make_metadata = tuf.formats.RootFile.make_metadata
    from_metadata = tuf.formats.RootFile.from_metadata
    ROOT_SCHEMA = tuf.formats.ROOT_SCHEMA

    self.assertTrue(ROOT_SCHEMA.matches(make_metadata(version, expiration_seconds,
                                                      keydict, roledict)))
    metadata = make_metadata(version, expiration_seconds, keydict, roledict,)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.RootFile))

    # Test conditions for invalid arguments.
    bad_version = '8'
    bad_expiration_seconds = 'eight'
    bad_keydict = 123
    bad_roledict = 123

    self.assertRaises(tuf.FormatError, make_metadata, bad_version,
                                                      expiration_seconds,
                                                      keydict, roledict)
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      bad_expiration_seconds,
                                                      keydict, roledict)
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      expiration_seconds,
                                                      bad_keydict, roledict)
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      expiration_seconds,
                                                      keydict, bad_roledict)

    self.assertRaises(tuf.FormatError, from_metadata, 'bad')



  def test_ReleaseFile(self):
    # Test conditions for valid instances of 'tuf.formats.ReleaseFile'.
    version = 8
    expires = '2012-10-16 06:42:12 UTC'
    filedict = {'metadata/release.txt': {'length': 1024,
                                         'hashes': {'sha256': 'ABCD123'},
                                         'custom': {'type': 'metadata'}}}

    make_metadata = tuf.formats.ReleaseFile.make_metadata
    from_metadata = tuf.formats.ReleaseFile.from_metadata
    RELEASE_SCHEMA = tuf.formats.RELEASE_SCHEMA

    self.assertTrue(RELEASE_SCHEMA.matches(make_metadata(version, expires,
                                                         filedict)))
    metadata = make_metadata(version, expires, filedict)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.ReleaseFile))

    # Test conditions for invalid arguments.
    bad_version = '8'
    bad_expires = '2000'
    bad_filedict = 123
    self.assertRaises(tuf.FormatError, make_metadata, version,
                                                      expires, bad_filedict)
    self.assertRaises(tuf.FormatError, make_metadata, bad_version, expires, 
                                                      filedict)
    self.assertRaises(tuf.FormatError, make_metadata, version, bad_expires,
                                                      bad_filedict)
    
    self.assertRaises(tuf.FormatError, from_metadata, 123)



  def test_TargetsFile(self):
    # Test conditions for valid instances of 'tuf.formats.TargetsFile'.
    version = 8
    expires = '2012-10-16 06:42:12 UTC'
    filedict = {'metadata/targets.txt': {'length': 1024,
                                         'hashes': {'sha256': 'ABCD123'},
                                         'custom': {'type': 'metadata'}}}

    delegations = {'keys': {'123abc': {'keytype':'rsa',
                                       'keyval': {'public': 'pubkey',
                                                  'private': 'privkey'}}},
                   'roles': [{'name': 'root', 'keyids': ['123abc'],
                              'threshold': 1, 'paths': ['path1/', 'path2']}]}

    make_metadata = tuf.formats.TargetsFile.make_metadata
    from_metadata = tuf.formats.TargetsFile.from_metadata
    TARGETS_SCHEMA = tuf.formats.TARGETS_SCHEMA

    self.assertTrue(TARGETS_SCHEMA.matches(make_metadata(version, expires,
                                                         filedict, delegations)))
    metadata = make_metadata(version, expires, filedict, delegations)
    self.assertTrue(isinstance(from_metadata(metadata), tuf.formats.TargetsFile))

    # Test conditions for invalid arguments.
    bad_version = 'eight'
    bad_expires = '2000'
    bad_filedict = 123
    bad_delegations = 123
    self.assertRaises(tuf.FormatError, make_metadata, bad_version, expires,
                                                      filedict, delegations)
    self.assertRaises(tuf.FormatError, make_metadata, version, bad_expires,
                                                      filedict, delegations)
    self.assertRaises(tuf.FormatError, make_metadata, version, expires,
                                                      bad_filedict, delegations)
    self.assertRaises(tuf.FormatError, make_metadata, version, expires,
                                                      filedict, bad_delegations)
    self.assertRaises(tuf.Error, make_metadata, version, expires)

    self.assertRaises(tuf.FormatError, from_metadata, 123)



  def test_format_time(self):
    # Test conditions for valid arguments.
    TIME_SCHEMA = tuf.formats.TIME_SCHEMA 
    self.assertTrue(TIME_SCHEMA.matches(tuf.formats.format_time(499137720)))
    self.assertEqual('1985-10-26 01:22:00 UTC', tuf.formats.format_time(499137720))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.formats.format_time, 'bad')
    self.assertRaises(tuf.FormatError, tuf.formats.format_time, 1000000000000000000000)
    self.assertRaises(tuf.FormatError, tuf.formats.format_time, ['5'])



  def test_parse_time(self):
    # Test conditions for valid arguments.
    self.assertEqual(499137600, tuf.formats.parse_time('1985-10-26 01:20:00 UTC'))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.formats.parse_time, 'bad')
    self.assertRaises(tuf.FormatError, tuf.formats.parse_time, 1000000000000000000000)
    self.assertRaises(tuf.FormatError, tuf.formats.parse_time, ['1'])



  def test_format_base64(self):
    # Test conditions for valid arguments.
    data = 'updateframework'
    self.assertEqual('dXBkYXRlZnJhbWV3b3Jr', tuf.formats.format_base64(data))
    self.assertTrue(isinstance(tuf.formats.format_base64(data), basestring))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, 123)
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, True)
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, ['123'])


  def test_parse_base64(self):
    # Test conditions for valid arguments.
    base64 = 'dXBkYXRlZnJhbWV3b3Jr'
    self.assertEqual('updateframework', tuf.formats.parse_base64(base64))
    self.assertTrue(isinstance(tuf.formats.parse_base64(base64), basestring))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, 123)
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, True)
    self.assertRaises(tuf.FormatError, tuf.formats.format_base64, ['123'])



  def test_make_signable(self):
    # Test conditions for expected make_signable() behavior.
    root = {'_type': 'Root',
            'version': 8,
            'expires': '2012-10-16 06:42:12 UTC',
            'keys': {'123abc': {'keytype': 'rsa',
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
    custom = {'type': 'paintjob'}
   
    FILEINFO_SCHEMA = tuf.formats.FILEINFO_SCHEMA
    make_fileinfo = tuf.formats.make_fileinfo
    self.assertTrue(FILEINFO_SCHEMA.matches(make_fileinfo(length, hashes, custom)))
    self.assertTrue(FILEINFO_SCHEMA.matches(make_fileinfo(length, hashes)))

    # Test conditions for invalid arguments.
    bad_length = 'bad'
    bad_hashes = 'bad'
    bad_custom = 'bad'

    self.assertRaises(tuf.FormatError, make_fileinfo, bad_length, hashes, custom)
    self.assertRaises(tuf.FormatError, make_fileinfo, length, bad_hashes, custom)
    self.assertRaises(tuf.FormatError, make_fileinfo, length, hashes, bad_custom)
    self.assertRaises(tuf.FormatError, make_fileinfo, bad_length, hashes)
    self.assertRaises(tuf.FormatError, make_fileinfo, length, bad_hashes)



  def test_make_role_metadata(self):
    # Test conditions for valid arguments. 
    keyids = ['123abc', 'abc123']
    threshold = 2
    paths = ['path1/', 'path2']
    name = '123'

    ROLE_SCHEMA = tuf.formats.ROLE_SCHEMA
    make_role = tuf.formats.make_role_metadata

    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, name=name)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, paths=paths)))
    self.assertTrue(ROLE_SCHEMA.matches(make_role(keyids, threshold, name=name, paths=paths)))

    # Test conditions for invalid arguments.
    bad_keyids = 'bad'
    bad_threshold = 'bad'
    bad_paths = 'bad'
    bad_name = 123

    self.assertRaises(tuf.FormatError, make_role, bad_keyids, threshold)
    self.assertRaises(tuf.FormatError, make_role, keyids, bad_threshold)

    self.assertRaises(tuf.FormatError, make_role, bad_keyids, threshold, paths=paths)
    self.assertRaises(tuf.FormatError, make_role, keyids, bad_threshold, paths=paths)
    self.assertRaises(tuf.FormatError, make_role, keyids, threshold, paths=bad_paths)

    self.assertRaises(tuf.FormatError, make_role, bad_keyids, threshold, name=name)
    self.assertRaises(tuf.FormatError, make_role, keyids, bad_threshold, name=name)
    self.assertRaises(tuf.FormatError, make_role, keyids, threshold, name=bad_name)

    self.assertRaises(tuf.FormatError, make_role, bad_keyids, threshold, name=name, paths=paths)
    self.assertRaises(tuf.FormatError, make_role, keyids, bad_threshold, name=name, paths=paths)
    self.assertRaises(tuf.FormatError, make_role, keyids, threshold, name=bad_name, paths=paths)
    self.assertRaises(tuf.FormatError, make_role, keyids, threshold, name=name, paths=bad_paths)



  def test_get_role_class(self):
    # Test conditions for valid arguments.
    get_role_class = tuf.formats.get_role_class
    
    self.assertEqual(tuf.formats.RootFile, get_role_class('Root'))
    self.assertEqual(tuf.formats.TargetsFile, get_role_class('Targets'))
    self.assertEqual(tuf.formats.ReleaseFile, get_role_class('Release'))
    self.assertEqual(tuf.formats.TimestampFile, get_role_class('Timestamp'))
    self.assertEqual(tuf.formats.MirrorsFile, get_role_class('Mirrors'))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, get_role_class, 'role')
    self.assertRaises(tuf.FormatError, get_role_class, 'ROLE')
    self.assertRaises(tuf.FormatError, get_role_class, 'abcd')
    self.assertRaises(tuf.FormatError, get_role_class, 123)
    self.assertRaises(tuf.FormatError, get_role_class, tuf.formats.RootFile)



  def test_expected_meta_rolename(self):
    # Test conditions for valid arguments.
    expected_rolename = tuf.formats.expected_meta_rolename

    self.assertEqual('Root', expected_rolename('root'))
    self.assertEqual('Targets', expected_rolename('targets'))
    self.assertEqual('Release', expected_rolename('release'))
    self.assertEqual('Timestamp', expected_rolename('timestamp'))
    self.assertEqual('Mirrors', expected_rolename('mirrors'))
    self.assertEqual('Targets Role', expected_rolename('targets role'))
    self.assertEqual('Root', expected_rolename('Root'))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, expected_rolename, 123)
    self.assertRaises(tuf.FormatError, expected_rolename, tuf.formats.RootFile)
    self.assertRaises(tuf.FormatError, expected_rolename, True)



  def test_check_signable_object_format(self):
    # Test condition for a valid argument.
    root = {'_type': 'Root',
            'version': 8,
            'expires': '2012-10-16 06:42:12 UTC',
            'keys': {'123abc': {'keytype': 'rsa',
                                'keyval': {'public': 'pubkey',
                                           'private': 'privkey'}}},
            'roles': {'root': {'keyids': ['123abc'],
                               'threshold': 1,
                               'paths': ['path1/', 'path2']}}}
    
    root = tuf.formats.make_signable(root)
    self.assertEqual('root', tuf.formats.check_signable_object_format(root))

    # Test conditions for invalid arguments.
    check_signable = tuf.formats.check_signable_object_format
    self.assertRaises(tuf.FormatError, check_signable, 'Root')
    self.assertRaises(tuf.FormatError, check_signable, 123)
    self.assertRaises(tuf.FormatError, check_signable, tuf.formats.RootFile)
    self.assertRaises(tuf.FormatError, check_signable, True)

    saved_type = root['signed']['_type']
    del root['signed']['_type']
    self.assertRaises(tuf.FormatError, check_signable, root)
    root['signed']['_type'] = saved_type

    root['signed']['_type'] = 'root'
    self.assertRaises(tuf.FormatError, check_signable, root)
    root['signed']['_type'] = 'Root'

    del root['signed']['expires']
    self.assertRaises(tuf.FormatError, check_signable, root)



  def test_encode_canonical(self):
    # Test conditions for valid arguments.
    encode = tuf.formats.encode_canonical
    result = [] 
    output = result.append
    bad_output = 123

    self.assertEqual('""', encode(""))
    self.assertEqual('[1,2,3]', encode([1, 2, 3]))
    self.assertEqual('[1,2,3]', encode([1,2,3]))
    self.assertEqual('[]', encode([]))
    self.assertEqual('{"A":[99]}', encode({"A": [99]}))
    self.assertEqual('{"x":3,"y":2}', encode({"x": 3, "y": 2}))

    # Condition where 'encode()' sends the result the callable
    # 'output'.
    self.assertEqual(None, encode([1, 2, 3], output))
    self.assertEqual('[1,2,3]', ''.join(result))

    # Test conditions for invalid arguments.
    self.assertRaises(tuf.FormatError, encode, tuf.formats.RootFile)
    self.assertRaises(tuf.FormatError, encode, 8.0)
    self.assertRaises(tuf.FormatError, encode, {"x": 8.0})
    self.assertRaises(tuf.FormatError, encode, 8.0, output)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
