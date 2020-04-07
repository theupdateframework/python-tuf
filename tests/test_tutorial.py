#!/usr/bin/env python

"""
<Program Name>
  test_tutorial.py

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Regression test for the TUF tutorial as laid out in TUTORIAL.md.
  This essentially runs the tutorial and checks some results.

  There are a few deviations from the TUTORIAL.md instructions:
   - steps that involve user input (like passphrases) are modified slightly
     to not require user input
   - use of path separators '/' is replaced by join() calls. (We assume that
     when following the tutorial, users will correctly deal with path
     separators for their system if they happen to be using non-Linux systems.)
   - shell instructions are mimicked using Python commands

"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import unittest
import datetime # part of TUTORIAL.md
import os # part of TUTORIAL.md, but also needed separately
import shutil
import tempfile
import sys

if sys.version_info >= (3, 3):
  import unittest.mock as mock

else:
  import mock

from tuf.repository_tool import *   # part of TUTORIAL.md

import securesystemslib.exceptions

from securesystemslib.formats import encode_canonical # part of TUTORIAL.md
from securesystemslib.keys import create_signature # part of TUTORIAL.md


class TestTutorial(unittest.TestCase):
  def setUp(self):
    self.working_dir = os.getcwd()
    self.test_dir = os.path.realpath(tempfile.mkdtemp())
    os.chdir(self.test_dir)

  def tearDown(self):
    os.chdir(self.working_dir)
    shutil.rmtree(self.test_dir)

  def test_tutorial(self):
    """
    Run the TUTORIAL.md tutorial.
    Note that anywhere the tutorial provides a command that prompts for the
    user to enter a passphrase/password, this test is changed to simply provide
    that as an argument. It's not worth trying to arrange automated testing of
    the interactive password entry process here. Anywhere user entry has been
    skipped from the tutorial instructions, "# Skipping user entry of password"
    is written, with the original line below it, starting with ##.
    """

    # ----- Tutorial Section:  Keys

    generate_and_write_rsa_keypair('root_key', bits=2048, password='password')

    # Skipping user entry of password
    ## generate_and_write_rsa_keypair('root_key2')
    generate_and_write_rsa_keypair('root_key2', password='password')

    # Tutorial tells users to expect these files to exist:
    # ['root_key', 'root_key.pub', 'root_key2', 'root_key2.pub']
    for fname in ['root_key', 'root_key.pub', 'root_key2', 'root_key2.pub']:
      self.assertTrue(os.path.exists(fname))

    # Generate key pair at /path/to/KEYID
    fname = generate_and_write_rsa_keypair(password="password")
    self.assertTrue(os.path.exists(fname))


    # ----- Tutorial Section:  Import RSA Keys

    public_root_key = import_rsa_publickey_from_file('root_key.pub')

    # Skipping user entry of password
    ## private_root_key = import_rsa_privatekey_from_file('root_key')
    private_root_key = import_rsa_privatekey_from_file('root_key', 'password')

    # Skipping user entry of password
    ## import_rsa_privatekey_from_file('root_key')
    with self.assertRaises(securesystemslib.exceptions.CryptoError):
      import_rsa_privatekey_from_file('root_key', 'not_the_real_pw')



    # ----- Tutorial Section: Create and Import Ed25519 Keys

    # Skipping user entry of password
    ## generate_and_write_ed25519_keypair('ed25519_key')
    generate_and_write_ed25519_keypair('ed25519_key', password='password')

    public_ed25519_key = import_ed25519_publickey_from_file('ed25519_key.pub')

    # Skipping user entry of password
    ## private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key')
    private_ed25519_key = import_ed25519_privatekey_from_file(
        'ed25519_key', 'password')



    # ----- Tutorial Section: Create Top-level Metadata
    repository = create_new_repository('repository')
    repository.root.add_verification_key(public_root_key)
    self.assertTrue(repository.root.keys)

    public_root_key2 = import_rsa_publickey_from_file('root_key2.pub')
    repository.root.add_verification_key(public_root_key2)

    repository.root.threshold = 2
    private_root_key2 = import_rsa_privatekey_from_file(
        'root_key2', password='password')

    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with("Dirty roles: " + str(['root']))

    # Patch logger to assert that it accurately logs the repo's status. Since
    # the logger is called multiple times, we have to assert for the accurate
    # sequence of calls or rather its call arguments.
    with mock.patch("tuf.repository_lib.logger") as mock_logger:
      repository.status()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      self.assertListEqual([
        repr('targets') + " role contains 0 / 1 public keys.",
        repr('snapshot') + " role contains 0 / 1 public keys.",
        repr('timestamp') + " role contains 0 / 1 public keys.",
        repr('root') + " role contains 2 / 2 signatures.",
        repr('targets') + " role contains 0 / 1 signatures."
      ], [args[0] for args, _ in mock_logger.info.call_args_list])

    generate_and_write_rsa_keypair('targets_key', password='password')
    generate_and_write_rsa_keypair('snapshot_key', password='password')
    generate_and_write_rsa_keypair('timestamp_key', password='password')

    repository.targets.add_verification_key(import_rsa_publickey_from_file(
        'targets_key.pub'))
    repository.snapshot.add_verification_key(import_rsa_publickey_from_file(
        'snapshot_key.pub'))
    repository.timestamp.add_verification_key(import_rsa_publickey_from_file(
        'timestamp_key.pub'))

    # Skipping user entry of password
    ## private_targets_key = import_rsa_privatekey_from_file('targets_key')
    private_targets_key = import_rsa_privatekey_from_file(
        'targets_key', 'password')

    # Skipping user entry of password
    ## private_snapshot_key = import_rsa_privatekey_from_file('snapshot_key')
    private_snapshot_key = import_rsa_privatekey_from_file(
        'snapshot_key', 'password')

    # Skipping user entry of password
    ## private_timestamp_key = import_rsa_privatekey_from_file('timestamp_key')
    private_timestamp_key = import_rsa_privatekey_from_file(
        'timestamp_key', 'password')

    repository.targets.load_signing_key(private_targets_key)
    repository.snapshot.load_signing_key(private_snapshot_key)
    repository.timestamp.load_signing_key(private_timestamp_key)

    repository.timestamp.expiration = datetime.datetime(2080, 10, 28, 12, 8)

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with("Dirty roles: " +
            str(['root', 'snapshot', 'targets', 'timestamp']))

    repository.writeall()



    # ----- Tutorial Section: Targets
    # These next commands in the tutorial are shown as bash commands, so I'll
    # just simulate this with some Python commands.
    ## $ cd repository/targets/
    ## $ echo 'file1' > file1.txt
    ## $ echo 'file2' > file2.txt
    ## $ echo 'file3' > file3.txt
    ## $ mkdir myproject; echo 'file4' > myproject/file4.txt
    ## $ cd ../../

    with open(os.path.join('repository', 'targets', 'file1.txt'), 'w') as fobj:
      fobj.write('file1')
    with open(os.path.join('repository', 'targets', 'file2.txt'), 'w') as fobj:
      fobj.write('file2')
    with open(os.path.join('repository', 'targets', 'file3.txt'), 'w') as fobj:
      fobj.write('file3')

    os.mkdir(os.path.join('repository', 'targets', 'myproject'))
    with open(os.path.join('repository', 'targets', 'myproject', 'file4.txt'),
        'w') as fobj:
      fobj.write('file4')


    repository = load_repository('repository')

    # TODO: replace the hard-coded list of targets with a helper
    # method that returns a list of normalized relative target paths
    list_of_targets = ['file1.txt', 'file2.txt', 'file3.txt']

    repository.targets.add_targets(list_of_targets)

    self.assertTrue('file1.txt' in repository.targets.target_files)
    self.assertTrue('file2.txt' in repository.targets.target_files)
    self.assertTrue('file3.txt' in repository.targets.target_files)

    target4_filepath = 'myproject/file4.txt'
    target4_abspath = os.path.abspath(os.path.join(
        'repository', 'targets', target4_filepath))
    octal_file_permissions = oct(os.stat(target4_abspath).st_mode)[4:]
    custom_file_permissions = {'file_permissions': octal_file_permissions}
    repository.targets.add_target(target4_filepath, custom_file_permissions)
    # Note that target filepaths specified in the repo use '/' even on Windows.
    # (This is important to make metadata platform-independent.)
    self.assertTrue(
        os.path.join(target4_filepath) in repository.targets.target_files)


    # Skipping user entry of password
    ## private_targets_key = import_rsa_privatekey_from_file('targets_key')
    private_targets_key = import_rsa_privatekey_from_file(
        'targets_key', 'password')
    repository.targets.load_signing_key(private_targets_key)

    # Skipping user entry of password
    ## private_snapshot_key = import_rsa_privatekey_from_file('snapshot_key')
    private_snapshot_key = import_rsa_privatekey_from_file(
        'snapshot_key', 'password')
    repository.snapshot.load_signing_key(private_snapshot_key)

    # Skipping user entry of password
    ## private_timestamp_key = import_rsa_privatekey_from_file('timestamp_key')
    private_timestamp_key = import_rsa_privatekey_from_file(
        'timestamp_key', 'password')
    repository.timestamp.load_signing_key(private_timestamp_key)

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with(
          "Dirty roles: " + str(['snapshot', 'targets', 'timestamp']))

    repository.writeall()

    repository.targets.remove_target('myproject/file4.txt')
    self.assertTrue(os.path.exists(os.path.join(
        'repository','targets', 'myproject', 'file4.txt')))

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with(
          "Dirty roles: " + str(['targets']))

    repository.mark_dirty(['snapshot', 'timestamp'])
    repository.writeall()


    # ----- Tutorial Section: Excursion: Dump Metadata and Append Signature
    signable_content = dump_signable_metadata(
        os.path.join('repository', 'metadata.staged', 'timestamp.json'))

    # Skipping user entry of password
    ## private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key')
    private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key', 'password')
    signature = create_signature(
        private_ed25519_key, encode_canonical(signable_content).encode())
    append_signature(
        signature,
        os.path.join('repository', 'metadata.staged', 'timestamp.json'))



    # ----- Tutorial Section: Delegations
    generate_and_write_rsa_keypair(
        'unclaimed_key', bits=2048, password='password')
    public_unclaimed_key = import_rsa_publickey_from_file('unclaimed_key.pub')
    repository.targets.delegate(
        'unclaimed', [public_unclaimed_key], ['myproject/*.txt'])

    repository.targets("unclaimed").add_target("myproject/file4.txt")

    # Skipping user entry of password
    ## private_unclaimed_key = import_rsa_privatekey_from_file('unclaimed_key')
    private_unclaimed_key = import_rsa_privatekey_from_file(
        'unclaimed_key', 'password')
    repository.targets("unclaimed").load_signing_key(private_unclaimed_key)

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with(
          "Dirty roles: " + str(['targets', 'unclaimed']))

    repository.mark_dirty(["snapshot", "timestamp"])
    repository.writeall()


    # Simulate the following shell command:
    ## $ cp -r "repository/metadata.staged/" "repository/metadata/"
    shutil.copytree(
        os.path.join('repository', 'metadata.staged'),
        os.path.join('repository', 'metadata'))


    # ----- Tutorial Section: Delegate to Hashed Bins
    repository.targets('unclaimed').remove_target("myproject/file4.txt")

    targets = ['myproject/file4.txt']

    # Patch logger to assert that it accurately logs the output of hashed bin
    # delegation. The logger is called multiple times, first with info level
    # then with warning level. So we have to assert for the accurate sequence
    # of calls or rather its call arguments.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.targets('unclaimed').delegate_hashed_bins(
          targets, [public_unclaimed_key], 32)

      self.assertListEqual([
            "Creating hashed bin delegations.\n"
            "1 total targets.\n"
            "32 hashed bins.\n"
            "256 total hash prefixes.\n"
            "Each bin ranges over 8 hash prefixes."
          ] + ["Adding a verification key that has already been used."] * 32,
          [
            args[0] for args, _ in
              mock_logger.info.call_args_list + mock_logger.warning.call_args_list
          ])


    for delegation in repository.targets('unclaimed').delegations:
      delegation.load_signing_key(private_unclaimed_key)

    # NOTE: The tutorial does not call dirty_roles anymore due to #964 and
    # #958. We still call it here to see if roles are dirty as expected.
    with mock.patch("tuf.repository_tool.logger") as mock_logger:
      repository.dirty_roles()
      # Concat strings to avoid Python2/3 unicode prefix problems ('' vs. u'')
      mock_logger.info.assert_called_with(
          "Dirty roles: " + str(['00-07', '08-0f', '10-17', '18-1f', '20-27',
          '28-2f', '30-37', '38-3f', '40-47', '48-4f', '50-57', '58-5f',
          '60-67', '68-6f', '70-77', '78-7f', '80-87', '88-8f', '90-97',
          '98-9f', 'a0-a7', 'a8-af', 'b0-b7', 'b8-bf', 'c0-c7', 'c8-cf',
          'd0-d7', 'd8-df', 'e0-e7', 'e8-ef', 'f0-f7', 'f8-ff', 'unclaimed']))

    repository.mark_dirty(["snapshot", "timestamp"])
    repository.writeall()

    # ----- Tutorial Section: How to Perform an Update

    # A separate tutorial is linked to for client use. That is not tested here.
    create_tuf_client_directory("repository/", "client/tufrepo/")



    # ----- Tutorial Section: Test TUF Locally

    # TODO: Run subprocess to simulate the following bash instructions:

    # $ cd "repository/"; python -m SimpleHTTPServer 8001
    # If running Python 3:

    # $ cd "repository/"; python3 -m http.server 8001
    # We next retrieve targets from the TUF repository and save them to client/. The client.py script is available to download metadata and files from a specified repository. In a different command-line prompt . . .

    # $ cd "client/"
    # $ ls
    # metadata/

    # $ client.py --repo http://localhost:8001 file1.txt
    # $ ls . targets/
    # .:
    # metadata  targets

    # targets/:
    # file1.txt



# Run unit test.
if __name__ == '__main__':
  unittest.main()
