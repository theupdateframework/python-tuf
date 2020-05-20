#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  test_formats.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  October 2012.

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

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

      'RELPATH_SCHEMA': (tuf.formats.RELPATH_SCHEMA, 'metadata/root/'),

      'RELPATHS_SCHEMA': (tuf.formats.RELPATHS_SCHEMA,
                          ['targets/role1/', 'targets/role2/']),

      'PATH_SCHEMA': (securesystemslib.formats.PATH_SCHEMA, '/home/someuser/'),

      'PATHS_SCHEMA': (securesystemslib.formats.PATHS_SCHEMA,
                       ['/home/McFly/', '/home/Tannen/']),

      'URL_SCHEMA': (securesystemslib.formats.URL_SCHEMA,
                     'https://www.updateframework.com/'),

      'VERSION_SCHEMA': (tuf.formats.VERSION_SCHEMA,
                         {'major': 1, 'minor': 0, 'fix': 8}),

      'LENGTH_SCHEMA': (tuf.formats.LENGTH_SCHEMA, 8),

      'NAME_SCHEMA': (securesystemslib.formats.NAME_SCHEMA, 'Marty McFly'),

      'BOOLEAN_SCHEMA': (securesystemslib.formats.BOOLEAN_SCHEMA, True),

      'THRESHOLD_SCHEMA': (tuf.formats.THRESHOLD_SCHEMA, 1),

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

      'TARGETS_FILEINFO_SCHEMA': (tuf.formats.TARGETS_FILEINFO_SCHEMA,
                                  {'length': 1024,
                                  'hashes': {'sha256': 'A4582BCF323BCEF'},
                                  'custom': {'type': 'paintjob'}}),

      'METADATA_FILEINFO_SCHEMA': (tuf.formats.METADATA_FILEINFO_SCHEMA,
                                   {'length': 1024,
                                    'hashes': {'sha256': 'A4582BCF323BCEF'},
                                    'version': 1}),

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

      'SIGNATURESTATUS_SCHEMA': (tuf.formats.SIGNATURESTATUS_SCHEMA,
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

      'KEYDB_SCHEMA': (tuf.formats.KEYDB_SCHEMA,
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
                       'spec_version': '1.0.0',
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
         'spec_version': '1.0.0',
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
         'spec_version': '1.0.0',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'snapshot.json': {'version': 1024}}}),

      'TIMESTAMP_SCHEMA': (tuf.formats.TIMESTAMP_SCHEMA,
        {'_type': 'timestamp',
         'spec_version': '1.0.0',
         'version': 8,
         'expires': '1985-10-21T13:20:00Z',
         'meta': {'metadattimestamp.json': {'length': 1024,
                                            'hashes': {'sha256': 'AB1245'},
                                            'version': 1}}}),

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
         'spec_version': '1.0.0',
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


  def test_specfication_version_schema(self):
    """Test valid and invalid SPECIFICATION_VERSION_SCHEMAs, using examples
    from 'regex101.com/r/Ly7O1x/3/', referenced by
    'semver.org/spec/v2.0.0.html'. """
    valid_schemas = [
        "0.0.4",
        "1.2.3",
        "10.20.30",
        "1.1.2-prerelease+meta",
        "1.1.2+meta",
        "1.1.2+meta-valid",
        "1.0.0-alpha",
        "1.0.0-beta",
        "1.0.0-alpha.beta",
        "1.0.0-alpha.beta.1",
        "1.0.0-alpha.1",
        "1.0.0-alpha0.valid",
        "1.0.0-alpha.0valid",
        "1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay",
        "1.0.0-rc.1+build.1",
        "2.0.0-rc.1+build.123",
        "1.2.3-beta",
        "10.2.3-DEV-SNAPSHOT",
        "1.2.3-SNAPSHOT-123",
        "1.0.0",
        "2.0.0",
        "1.1.7",
        "2.0.0+build.1848",
        "2.0.1-alpha.1227",
        "1.0.0-alpha+beta",
        "1.2.3----RC-SNAPSHOT.12.9.1--.12+788",
        "1.2.3----R-S.12.9.1--.12+meta",
        "1.2.3----RC-SNAPSHOT.12.9.1--.12",
        "1.0.0+0.build.1-rc.10000aaa-kk-0.1",
        "99999999999999999999999.999999999999999999.99999999999999999",
        "1.0.0-0A.is.legal"]

    for valid_schema in valid_schemas:
      self.assertTrue(
          tuf.formats.SPECIFICATION_VERSION_SCHEMA.matches(valid_schema),
          "'{}' should match 'SPECIFICATION_VERSION_SCHEMA'.".format(
          valid_schema))

    invalid_schemas = [
        "1",
        "1.2",
        "1.2.3-0123",
        "1.2.3-0123.0123",
        "1.1.2+.123",
        "+invalid",
        "-invalid",
        "-invalid+invalid",
        "-invalid.01",
        "alpha",
        "alpha.beta",
        "alpha.beta.1",
        "alpha.1",
        "alpha+beta",
        "alpha_beta",
        "alpha.",
        "alpha..",
        "beta",
        "1.0.0-alpha_beta",
        "-alpha.",
        "1.0.0-alpha..",
        "1.0.0-alpha..1",
        "1.0.0-alpha...1",
        "1.0.0-alpha....1",
        "1.0.0-alpha.....1",
        "1.0.0-alpha......1",
        "1.0.0-alpha.......1",
        "01.1.1",
        "1.01.1",
        "1.1.01",
        "1.2",
        "1.2.3.DEV",
        "1.2-SNAPSHOT",
        "1.2.31.2.3----RC-SNAPSHOT.12.09.1--..12+788",
        "1.2-RC-SNAPSHOT",
        "-1.0.3-gamma+b7718",
        "+justmeta",
        "9.8.7+meta+meta",
        "9.8.7-whatever+meta+meta",
        "99999999999999999999999.999999999999999999.99999999999999999----RC-SNAPSHOT.12.09.1--------------------------------..12"]

    for invalid_schema in invalid_schemas:
      self.assertFalse(
          tuf.formats.SPECIFICATION_VERSION_SCHEMA.matches(invalid_schema),
          "'{}' should not match 'SPECIFICATION_VERSION_SCHEMA'.".format(
          invalid_schema))


  def test_build_dict_conforming_to_schema(self):
    # Test construction of a few metadata formats using
    # build_dict_conforming_to_schema().

    # Try the wrong type of schema object.
    STRING_SCHEMA = securesystemslib.schema.AnyString()

    with self.assertRaises(ValueError):
      tuf.formats.build_dict_conforming_to_schema(
          STRING_SCHEMA, string='some string')

    # Try building Timestamp metadata.
    spec_version = tuf.SPECIFICATION_VERSION
    version = 8
    length = 88
    hashes = {'sha256': '3c7fe3eeded4a34'}
    expires = '1985-10-21T13:20:00Z'
    filedict = {'snapshot.json': {'length': length, 'hashes': hashes, 'version': 1}}


    # Try with and without _type and spec_version, both of which are
    # automatically populated if they are not included.
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches( # both
        tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TIMESTAMP_SCHEMA,
        _type='timestamp',
        spec_version=spec_version,
        version=version,
        expires=expires,
        meta=filedict)))
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches( # neither
        tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TIMESTAMP_SCHEMA,
        version=version,
        expires=expires,
        meta=filedict)))
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches( # one
        tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TIMESTAMP_SCHEMA,
        spec_version=spec_version,
        version=version,
        expires=expires,
        meta=filedict)))
    self.assertTrue(tuf.formats.TIMESTAMP_SCHEMA.matches( # the other
        tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.TIMESTAMP_SCHEMA,
        _type='timestamp',
        version=version,
        expires=expires,
        meta=filedict)))


    # Try test arguments for invalid Timestamp creation.
    bad_spec_version = 123
    bad_version = 'eight'
    bad_expires = '2000'
    bad_filedict = 123
    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TIMESTAMP_SCHEMA,
          _type='timestamp',
          spec_version=bad_spec_version,
          version=version,
          expires=expires,
          meta=filedict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TIMESTAMP_SCHEMA,
          _type='timestamp',
          spec_version=spec_version,
          version=bad_version,
          expires=expires,
          meta=filedict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TIMESTAMP_SCHEMA,
          _type='timestamp',
          spec_version=spec_version,
          version=version,
          expires=bad_expires,
          meta=filedict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TIMESTAMP_SCHEMA,
          _type='timestamp',
          spec_version=spec_version,
          version=version,
          expires=expires,
          meta=bad_filedict)

    with self.assertRaises(ValueError):
      tuf.formats.build_dict_conforming_to_schema(123)


    # Try building Root metadata.
    consistent_snapshot = False

    keydict = {'123abc': {'keytype': 'rsa',
                          'scheme': 'rsassa-pss-sha256',
                          'keyval': {'public': 'pubkey',
                                     'private': 'privkey'}}}

    roledict = {'root': {'keyids': ['123abc'],
                         'threshold': 1,
                         'paths': ['path1/', 'path2']}}


    self.assertTrue(tuf.formats.ROOT_SCHEMA.matches(
        tuf.formats.build_dict_conforming_to_schema(
        tuf.formats.ROOT_SCHEMA,
        _type='root',
        spec_version=spec_version,
        version=version,
        expires=expires,
        keys=keydict,
        roles=roledict,
        consistent_snapshot=consistent_snapshot)))


    # Additional test arguments for invalid Root creation.
    bad_keydict = 123
    bad_roledict = 123

    # TODO: Later on, write a test looper that takes pairs of key-value args
    #       to substitute in on each run to shorten this.... There's a lot of
    #       test code that looks like this, and it'd be easier to use a looper.

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA,
          _type='root',
          spec_version=bad_spec_version,
          version=version,
          expires=expires,
          keys=keydict,
          roles=roledict,
          consistent_snapshot=consistent_snapshot)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA,
          _type='root',
          spec_version=spec_version,
          version=bad_version,
          expires=expires,
          keys=keydict,
          roles=roledict,
          consistent_snapshot=consistent_snapshot)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA,
          _type='root',
          spec_version=spec_version,
          version=version,
          expires=bad_expires,
          keys=keydict,
          roles=roledict,
          consistent_snapshot=consistent_snapshot)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA,
          _type='root',
          spec_version=spec_version,
          version=version,
          expires=expires,
          keys=bad_keydict,
          roles=roledict,
          consistent_snapshot=consistent_snapshot)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA,
          _type='root',
          spec_version=spec_version,
          version=version,
          expires=expires,
          keys=keydict,
          roles=bad_roledict,
          consistent_snapshot=consistent_snapshot)

    with self.assertRaises(TypeError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.ROOT_SCHEMA, 'bad')

    with self.assertRaises(ValueError):
      tuf.formats.build_dict_conforming_to_schema(
          'bad',
          _type='root',
          spec_version=spec_version,
          version=version,
          expires=expires,
          keys=keydict,
          roles=roledict,
          consistent_snapshot=consistent_snapshot)



    # Try building Snapshot metadata.
    versiondict = {'targets.json' : {'version': version}}

    self.assertTrue(tuf.formats.SNAPSHOT_SCHEMA.matches(
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.SNAPSHOT_SCHEMA,
          _type='snapshot',
          spec_version=spec_version,
          version=version,
          expires=expires,
          meta=versiondict)))

    # Additional test arguments for invalid Snapshot creation.
    bad_versiondict = 123

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.SNAPSHOT_SCHEMA,
          _type='snapshot',
          spec_version=bad_spec_version,
          version=version,
          expires=expires,
          meta=versiondict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.SNAPSHOT_SCHEMA,
          _type='snapshot',
          spec_version=spec_version,
          version=bad_version,
          expires=expires,
          meta=versiondict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.SNAPSHOT_SCHEMA,
          _type='snapshot',
          spec_version=spec_version,
          version=version,
          expires=bad_expires,
          meta=versiondict)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.SNAPSHOT_SCHEMA,
          _type='snapshot',
          spec_version=spec_version,
          version=version,
          expires=expires,
          meta=bad_versiondict)



    # Try building Targets metadata.
    filedict = {'metadata/targets.json': {'length': 1024,
                                         'hashes': {'sha256': 'ABCD123'},
                                         'custom': {'type': 'metadata'}}}

    delegations = {'keys': {'123abc': {'keytype':'rsa',
                                       'scheme': 'rsassa-pss-sha256',
                                       'keyval': {'public': 'pubkey',
                                                  'private': 'privkey'}}},
                   'roles': [{'name': 'root', 'keyids': ['123abc'],
                              'threshold': 1, 'paths': ['path1/', 'path2']}]}


    self.assertTrue(tuf.formats.TARGETS_SCHEMA.matches(
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=version,
          expires=expires,
          targets=filedict,
          delegations=delegations)))

    # Try with no delegations included (should work, since they're optional).
    self.assertTrue(tuf.formats.TARGETS_SCHEMA.matches(
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=version,
          expires=expires,
          targets=filedict)))


    # Additional test arguments for invalid Targets creation.
    bad_filedict = 123
    bad_delegations = 123

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=bad_version,
          expires=expires,
          targets=filedict,
          delegations=delegations)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=version,
          expires=bad_expires,
          targets=filedict,
          delegations=delegations)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=version,
          expires=expires,
          targets=bad_filedict,
          delegations=delegations)

    with self.assertRaises(securesystemslib.exceptions.FormatError):
      tuf.formats.build_dict_conforming_to_schema(
          tuf.formats.TARGETS_SCHEMA,
          _type='targets',
          spec_version=spec_version,
          version=version,
          expires=expires,
          targets=filedict,
          delegations=bad_delegations)





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
            'spec_version': '1.0.0',
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





  def test_make_targets_fileinfo(self):
    # Test conditions for valid arguments.
    length = 1024
    hashes = {'sha256': 'A4582BCF323BCEF', 'sha512': 'A4582BCF323BFEF'}
    custom = {'type': 'paintjob'}

    TARGETS_FILEINFO_SCHEMA = tuf.formats.TARGETS_FILEINFO_SCHEMA
    make_targets_fileinfo = tuf.formats.make_targets_fileinfo
    self.assertTrue(TARGETS_FILEINFO_SCHEMA.matches(make_targets_fileinfo(length, hashes, custom)))
    self.assertTrue(TARGETS_FILEINFO_SCHEMA.matches(make_targets_fileinfo(length, hashes)))

    # Test conditions for invalid arguments.
    bad_length = 'bad'
    bad_hashes = 'bad'
    bad_custom = 'bad'

    self.assertRaises(securesystemslib.exceptions.FormatError, make_targets_fileinfo,
      bad_length, hashes, custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_targets_fileinfo,
      length, bad_hashes, custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_targets_fileinfo,
      length, hashes, bad_custom)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_targets_fileinfo,
      bad_length, hashes)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_targets_fileinfo,
      length, bad_hashes)



  def test_make_metadata_fileinfo(self):
    # Test conditions for valid arguments.
    length = 1024
    hashes = {'sha256': 'A4582BCF323BCEF', 'sha512': 'A4582BCF323BFEF'}
    version = 8

    METADATA_FILEINFO_SCHEMA = tuf.formats.METADATA_FILEINFO_SCHEMA
    make_metadata_fileinfo = tuf.formats.make_metadata_fileinfo
    self.assertTrue(METADATA_FILEINFO_SCHEMA.matches(make_metadata_fileinfo(
        version, length, hashes)))
    self.assertTrue(METADATA_FILEINFO_SCHEMA.matches(make_metadata_fileinfo(version)))

    # Test conditions for invalid arguments.
    bad_version = 'bad'
    bad_length = 'bad'
    bad_hashes = 'bad'

    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata_fileinfo,
        bad_version, length, hashes)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata_fileinfo,
        version, bad_length, hashes)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata_fileinfo,
        version, length, bad_hashes)
    self.assertRaises(securesystemslib.exceptions.FormatError, make_metadata_fileinfo,
        bad_version)



  def test_make_versioninfo(self):
    # Test conditions for valid arguments.
    version_number = 8
    versioninfo = {'version': version_number}

    VERSIONINFO_SCHEMA = tuf.formats.VERSIONINFO_SCHEMA
    make_versioninfo = tuf.formats.make_versioninfo
    self.assertTrue(VERSIONINFO_SCHEMA.matches(make_versioninfo(version_number)))

    # Test conditions for invalid arguments.
    bad_version_number = '8'

    self.assertRaises(securesystemslib.exceptions.FormatError, make_versioninfo, bad_version_number)





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
    self.assertRaises(securesystemslib.exceptions.FormatError, expected_rolename, tuf.formats.ROOT_SCHEMA)
    self.assertRaises(securesystemslib.exceptions.FormatError, expected_rolename, True)



  def test_check_signable_object_format(self):
    # Test condition for a valid argument.
    root = {'_type': 'root',
            'spec_version': '1.0.0',
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
    self.assertRaises(securesystemslib.exceptions.FormatError, check_signable, tuf.formats.ROOT_SCHEMA)
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
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, tuf.formats.ROOT_SCHEMA)
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0)
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": 8.0})
    self.assertRaises(securesystemslib.exceptions.FormatError, encode, 8.0, output)

    self.assertRaises(securesystemslib.exceptions.FormatError, encode, {"x": securesystemslib.exceptions.FormatError})


# Run unit test.
if __name__ == '__main__':
  unittest.main()
