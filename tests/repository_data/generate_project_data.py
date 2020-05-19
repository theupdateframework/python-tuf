#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  generate_project_data.py

<Author>
  Santiago Torres <torresariass@gmail.com>

<Started>
  January 22, 2014.

<Copyright>
  See LICENSE-MIT.txt OR LICENSE-APACHE.txt for licensing information.

<Purpose>
  Generate a pre-fabricated set of metadata files for 'test_developer_tool.py'
  test cases.
"""

import shutil
import datetime
import optparse
import os

from tuf.developer_tool import *

import securesystemslib

parser = optparse.OptionParser()

parser.add_option("-d","--dry-run", action='store_true', dest="dry_run",
    help="Do not write the files, just run", default=False)
(options, args) = parser.parse_args()


project_key_file = 'keystore/root_key'
targets_key_file = 'keystore/targets_key'
delegation_key_file = 'keystore/delegation_key'

# The files we use for signing in the unit tests should exist, if they are not
# populated, run 'generate.py'.
assert os.path.exists(project_key_file)
assert os.path.exists(targets_key_file)
assert os.path.exists(delegation_key_file)

# Import the public keys.  These keys are needed so that metadata roles are
# assigned verification keys, which clients use to verify the signatures created
# by the corresponding private keys.
project_public = import_rsa_publickey_from_file(project_key_file + '.pub')
targets_public = import_ed25519_publickey_from_file(targets_key_file + '.pub')
delegation_public = import_ed25519_publickey_from_file(delegation_key_file + '.pub')

# Import the private keys.  These private keys are needed to generate the
# signatures included in metadata.
project_private = import_rsa_privatekey_from_file(project_key_file, 'password')
targets_private = import_ed25519_privatekey_from_file(targets_key_file, 'password')
delegation_private = import_ed25519_privatekey_from_file(delegation_key_file, 'password')

os.mkdir("project")
os.mkdir("project/targets")

# Create the target files (downloaded by clients) whose file size and digest
# are specified in the 'targets.json' file.
target1_filepath = 'project/targets/file1.txt'
securesystemslib.util.ensure_parent_dir(target1_filepath)
target2_filepath = 'project/targets/file2.txt'
securesystemslib.util.ensure_parent_dir(target2_filepath)
target3_filepath = 'project/targets/file3.txt'
securesystemslib.util.ensure_parent_dir(target2_filepath)

if not options.dry_run:
  with open(target1_filepath, 'wt') as file_object:
    file_object.write('This is an example target file.')

  with open(target2_filepath, 'wt') as file_object:
    file_object.write('This is an another example target file.')

  with open(target3_filepath, 'wt') as file_object:
    file_object.write('This is role1\'s target file.')


project = create_new_project("test-flat", 'project/test-flat', 'prefix', 'project/targets')

# Add target files to the top-level projects role.  These target files should
# already exist.
project.add_target('file1.txt')
project.add_target('file2.txt')

# Add one key to the project.
project.add_verification_key(project_public)
project.load_signing_key(project_private)

# Add the delegated role keys.
project.delegate('role1', [delegation_public], [target3_filepath])
project('role1').load_signing_key(delegation_private)

# Set the project expiration time far into the future so that its metadata does
# not expire anytime soon, or else the tests fail.  Unit tests may modify the
# expiration  datetimes (of the copied files), if they wish.
project.expiration = datetime.datetime(2030, 1, 1, 0, 0)
project('role1').expiration = datetime.datetime(2030, 1, 1, 0, 0)

# Create the actual metadata files, which are saved to 'metadata.staged'.
if not options.dry_run:
  project.write()
