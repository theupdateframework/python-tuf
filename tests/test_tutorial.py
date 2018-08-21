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

from tuf.repository_tool import *   # part of TUTORIAL.md

import securesystemslib.exceptions


class TestTutorial(unittest.TestCase):
  def setUp(self):
    clean_test_environment()



  def tearDown(self):
    clean_test_environment()



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
    repo = create_new_repository("my_repo")



    # ----- Tutorial Section:  Keys

    generate_and_write_rsa_keypair('root_key', bits=2048, password='password')

    # Skipping user entry of password
    ## generate_and_write_rsa_keypair('root_key2')
    generate_and_write_rsa_keypair('root_key2', password='password')

    # Tutorial tells users to expect these files to exist:
    # ['root_key', 'root_key.pub', 'root_key2', 'root_key2.pub']
    for fname in ['root_key', 'root_key.pub', 'root_key2', 'root_key2.pub']:
      self.assertTrue(os.path.exists(fname))

    # Note: Skipping the creation of an effectively-randomly named key file, as
    # that is harder to clean up.
    ## generate_and_write_rsa_keypair()



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


    # TODO: dirty_roles() doesn't return the list of dirty roles; it just
    # prints the list. It should probably it should return it as well.
    # If that's not changed, perhaps we should test the print output from the
    # dirty_roles() statement here.
    repository.dirty_roles()
    # self.assertEqual(repository.dirty_roles(), ['root'])


    # TODO: status() should return some sort of value that indicates what
    # it prints. It's currently just printing status information.
    # If that's not changed, perhaps we should test the print output from the
    # status() statement here.
    repository.status()


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
    list_of_targets = repository.get_filepaths_in_directory(
        os.path.join('repository', 'targets'), recursive_walk=False, followlinks=True)

    # Ensure that we have absolute paths. (Harmless before and after PR #774,
    # which fixes the issue with non-absolute paths coming from
    # get_filepaths_in_directory.)

    list_of_targets_temp = []

    for t in list_of_targets:
      list_of_targets_temp.append(os.path.abspath(t))

    list_of_targets = list_of_targets_temp


    self.assertEqual(sorted(list_of_targets), [
        os.path.abspath(os.path.join('repository', 'targets', 'file1.txt')),
        os.path.abspath(os.path.join('repository', 'targets', 'file2.txt')),
        os.path.abspath(os.path.join('repository', 'targets', 'file3.txt'))])


    repository.targets.add_targets(list_of_targets)

    self.assertTrue('file1.txt' in repository.targets.target_files)
    self.assertTrue('file2.txt' in repository.targets.target_files)
    self.assertTrue('file3.txt' in repository.targets.target_files)


    target4_filepath = os.path.abspath(os.path.join(
        'repository', 'targets', 'myproject', 'file4.txt'))
    octal_file_permissions = oct(os.stat(target4_filepath).st_mode)[4:]
    custom_file_permissions = {'file_permissions': octal_file_permissions}
    repository.targets.add_target(target4_filepath, custom_file_permissions)
    # Note that target filepaths specified in the repo use '/' even on Windows.
    # (This is important to make metadata platform-independent.)
    self.assertTrue(
        os.path.join('myproject/file4.txt') in repository.targets.target_files)


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

    # TODO: dirty_roles() doesn't return the list of dirty roles; it just
    # prints the list. It should probably it should return it as well.
    # If that's not changed, perhaps we should test the print output from the
    # dirty_roles() statement here.
    repository.dirty_roles()
    # self.assertEqual(
    #   repository.dirty_roles(), ['timestamp', 'snapshot', 'targets'])

    repository.writeall()

    repository.targets.remove_target('file3.txt')
    self.assertTrue(os.path.exists(os.path.join(
        'repository','targets', 'file3.txt')))

    repository.writeall()

    signable_content = dump_signable_metadata(
        os.path.join('repository', 'metadata.staged', 'targets.json'))
    append_signature(
        {'keyid': '99aabb', 'sig': '000000'},
        os.path.join('repository', 'metadata.staged', 'targets.json'))



    # ----- Tutorial Section: Delegations
    generate_and_write_rsa_keypair(
        'unclaimed_key', bits=2048, password='password')
    public_unclaimed_key = import_rsa_publickey_from_file('unclaimed_key.pub')
    repository.targets.delegate(
        'unclaimed', [public_unclaimed_key], ['foo*.tgz'])

    # Skipping user entry of password
    ## private_unclaimed_key = import_rsa_privatekey_from_file('unclaimed_key')
    private_unclaimed_key = import_rsa_privatekey_from_file(
        'unclaimed_key', 'password')
    repository.targets("unclaimed").load_signing_key(private_unclaimed_key)

    repository.targets("unclaimed").version = 2

    # TODO: dirty_roles() doesn't return the list of dirty roles; it just
    # prints the list. It should probably it should return it as well.
    # If that's not changed, perhaps we should test the print output from the
    # dirty_roles() statement here.
    repository.dirty_roles()
    # self.assertEqual(repository.dirty_roles(),
    #   ['timestamp', 'snapshot', 'targets', 'unclaimed'])

    repository.writeall()

    repository.targets('unclaimed').delegate('django', [public_unclaimed_key], ['bar*.tgz'])
    repository.targets('unclaimed').revoke('django')
    repository.writeall()


    # Simulate the following shell command:
    ## $ cp -r "repository/metadata.staged/" "repository/metadata/"
    shutil.copytree(
        os.path.join('repository', 'metadata.staged'),
        os.path.join('repository', 'metadata'))



    # ----- Tutorial Section: Consistent Snapshots

    repository.root.load_signing_key(private_root_key)
    repository.root.load_signing_key(private_root_key2)
    repository.writeall(consistent_snapshot=True)



    # ----- Tutorial Section: Delegate to Hashed Bins

    targets = repository.get_filepaths_in_directory(
        os.path.join('repository', 'targets', 'myproject'), recursive_walk=True)

    for delegation in repository.targets('unclaimed').delegations:
      delegation.load_signing_key(private_unclaimed_key)



    # ----- Tutorial Section: How to Perform an Update

    # A separate tutorial is linked to for client use. That is not tested here.
    create_tuf_client_directory("repository/", "client/")



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





def clean_test_environment():
  """
  Delete temporary files and directories from this test (or with the same name
  as those created by this test...).
  """
  for directory in ['repository', 'my_repo', 'client',
      'repository/targets/my_project']:
    if os.path.exists(directory):
      shutil.rmtree(directory)

  for fname in [
        os.path.join('repository', 'targets', 'file1.txt'),
        os.path.join('repository', 'targets', 'file2.txt'),
        os.path.join('repository', 'targets', 'file3.txt'),
        'root_key',
        'root_key.pub',
        'root_key2',
        'root_key2.pub',
        'ed25519_key',
        'ed25519_key.pub',
        'targets_key',
        'targets_key.pub',
        'snapshot_key',
        'snapshot_key.pub',
        'timestamp_key',
        'timestamp_key.pub',
        'unclaimed_key',
        'unclaimed_key.pub']:
    if os.path.exists(fname):
      os.remove(fname)



# Run unit test.
if __name__ == '__main__':
  unittest.main()
