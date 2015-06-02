#!/usr/bin/env python

"""
<Program Name>
  test_hash.py

<Authors>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  Refactored March 1, 2012 (VLAD).  Based on a previous version of this module.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Unit test for 'hash.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import os
import logging
import tempfile
import unittest

import tuf
import tuf.log
import tuf.hash

import six

logger = logging.getLogger('tuf.test_hash')


if not 'hashlib' in tuf.hash._supported_libraries:
  logger.warn('Not testing hashlib: could not be imported.')
if not 'pycrypto' in tuf.hash._supported_libraries:
  logger.warn('Not testing pycrypto: could not be imported.')

class TestHash(unittest.TestCase):

  def _run_with_all_hash_libraries(self, test_func):
    if 'hashlib' in tuf.hash._supported_libraries:
      test_func('hashlib')
    if 'pycrypto' in tuf.hash._supported_libraries:
      test_func('pycrypto')


  def test_md5_update(self):
    self._run_with_all_hash_libraries(self._do_md5_update)


  def _do_md5_update(self, library):
    digest_object = tuf.hash.digest('md5', library)
    self.assertEqual(digest_object.hexdigest(),
                    'd41d8cd98f00b204e9800998ecf8427e')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    '0cc175b9c0f1b6a831c399e269772661')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'f034e93091235adbb5d2781908e2b313')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'f034e93091235adbb5d2781908e2b313')


  def test_sha1_update(self):
    self._run_with_all_hash_libraries(self._do_sha1_update)


  def _do_sha1_update(self, library):
    digest_object = tuf.hash.digest('sha1', library)

    self.assertEqual(digest_object.hexdigest(), 
                    'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    '86f7e437faa5a7fce15d1ddcb9eaeaea377667b8')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'd7bfa42fc62b697bf6cf1cda9af1fb7f40a27817')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'd7bfa42fc62b697bf6cf1cda9af1fb7f40a27817')


  def test_sha224_update(self):
    self._run_with_all_hash_libraries(self._do_sha224_update)


  def _do_sha224_update(self, library):
    digest_object = tuf.hash.digest('sha224', library)

    self.assertEqual(digest_object.hexdigest(),
                    'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'ab1342f31c2a6f242d9a3cefb503fb49465c95eb255c16ad791d688c')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
                    'ab1342f31c2a6f242d9a3cefb503fb49465c95eb255c16ad791d688c')


  def test_sha256_update(self):
    self._run_with_all_hash_libraries(self._do_sha256_update)


  def _do_sha256_update(self, library):
    digest_object = tuf.hash.digest('sha256', library)
    self.assertEqual(digest_object.hexdigest(),
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
            'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
            '01d162a5c95d4698c0a3e766ae80d85994b549b877ed275803725f43dadc83bd')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
            '01d162a5c95d4698c0a3e766ae80d85994b549b877ed275803725f43dadc83bd')


  def test_sha384_update(self):
    self._run_with_all_hash_libraries(self._do_sha384_update)


  def _do_sha384_update(self, library):
    digest_object = tuf.hash.digest('sha384', library)
    self.assertEqual(digest_object.hexdigest(),
    '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe'
    '76f65fbd51ad2f14898b95b')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(), 
    '54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d'
    '57bc35efae0b5afd3145f31')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
    'f2c1438e9cc1d24bebbf3b88e60adc169db0c5c459d02054ec131438bf20ebee5ca88c17c'
    'b5f1a824fcccf8d2b20b0a9')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
    'f2c1438e9cc1d24bebbf3b88e60adc169db0c5c459d02054ec131438bf20ebee5ca88c17c'
    'b5f1a824fcccf8d2b20b0a9')


  def test_sha512_update(self):
    self._run_with_all_hash_libraries(self._do_sha512_update)


  def _do_sha512_update(self, library):
    digest_object = tuf.hash.digest('sha512', library)

    self.assertEqual(digest_object.hexdigest(),
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5'
    'd85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
    digest_object.update('a'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(), 
    '1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652'
    'bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75')
    digest_object.update('bbb'.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
    '09ade82ae3c5d54f8375f348563a372106488adef16a74b63b5591849f740bff55ceab22e'
    '117b4b09349b860f8a644adb32a9ea542abdecb80bf625160604251')
    digest_object.update(''.encode('utf-8'))
    self.assertEqual(digest_object.hexdigest(),
    '09ade82ae3c5d54f8375f348563a372106488adef16a74b63b5591849f740bff55ceab22e'
    '117b4b09349b860f8a644adb32a9ea542abdecb80bf625160604251')


  def test_unsupported_algorithm(self):
    self._run_with_all_hash_libraries(self._do_unsupported_algorithm)


  def _do_unsupported_algorithm(self, library):
    self.assertRaises(tuf.UnsupportedAlgorithmError, tuf.hash.digest, 'bogus')


  def test_digest_size(self):
    self._run_with_all_hash_libraries(self._do_digest_size)


  def _do_digest_size(self, library):
    self.assertEqual(16, tuf.hash.digest('md5', library).digest_size)
    self.assertEqual(20, tuf.hash.digest('sha1', library).digest_size)
    self.assertEqual(28, tuf.hash.digest('sha224', library).digest_size)
    self.assertEqual(32, tuf.hash.digest('sha256', library).digest_size)
    self.assertEqual(48, tuf.hash.digest('sha384', library).digest_size)
    self.assertEqual(64, tuf.hash.digest('sha512', library).digest_size)


  def test_update_filename(self):
    self._run_with_all_hash_libraries(self._do_update_filename)


  def _do_update_filename(self, library):
    data = 'abcdefgh' * 4096
    fd, filename = tempfile.mkstemp()
    try:
      os.write(fd, data.encode('utf-8'))
      os.close(fd)
      for algorithm in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
        digest_object_truth = tuf.hash.digest(algorithm, library)
        digest_object_truth.update(data.encode('utf-8'))
        digest_object = tuf.hash.digest_filename(filename, algorithm, library)
        self.assertEqual(digest_object_truth.digest(), digest_object.digest())
    
    finally:
        os.remove(filename)


  def test_update_file_obj(self):
    self._run_with_all_hash_libraries(self._do_update_file_obj)


  def _do_update_file_obj(self, library):
    data = 'abcdefgh' * 4096
    file_obj = six.StringIO()
    file_obj.write(data)
    for algorithm in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
      digest_object_truth = tuf.hash.digest(algorithm, library)
      digest_object_truth.update(data.encode('utf-8'))
      digest_object = tuf.hash.digest_fileobject(file_obj, algorithm, library)
      # Note: we don't seek because the update_file_obj call is supposed
      # to always seek to the beginning.
      self.assertEqual(digest_object_truth.digest(), digest_object.digest())


  def test_unsupported_digest_algorithm_and_library(self):
    self.assertRaises(tuf.UnsupportedAlgorithmError, tuf.hash.digest,
                      'sha123', 'hashlib')
    self.assertRaises(tuf.UnsupportedAlgorithmError, tuf.hash.digest,
                      'sha123', 'pycrypto')
    
    self.assertRaises(tuf.UnsupportedLibraryError, tuf.hash.digest,
                      'sha256', 'badlib')


# Run unit test.
if __name__ == '__main__':
  unittest.main()
