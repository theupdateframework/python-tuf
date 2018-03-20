#!/usr/bin/env python

"""
<Program Name>
  tuf_cli.py

<Author>
  Artiom Baloian <artiom.baloian@nyu.edu>

<Started>
  January 27, 2017

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provide a CLI for the Repository Management Tools.
  See 'tuf/README' for the complete guide to using.
"""

import tuf
from tuf.repository_tool import *
from os.path import expanduser
from optparse import OptionParser


# Write initialized repository path into the file (.tuf_repo_path)
# .tuf_repo_path file is going to be created in the home directory.
# Argument is repository root path
# TODO What happens if user runs more than one repository from a single CLI?
def write_repo_path_to_file(repo_path):
  repo_file_path = expanduser("~") + "/.tuf_repo_path"
  repo_file = open(repo_file_path, 'w')
  repo_file.write(repo_path)
  repo_file.close()



# Read initialized repository path from the file (.tuf_repo_path)
# .tuf_repo_path file is going to be created in the home directory.
# Return repository path as a string
def read_repo_path_from_file():
  repo_file_path = expanduser("~") + "/.tuf_repo_path"
  if not os.path.isfile(repo_file_path):
    print "File ", repo_file_path, " does not exist"
    return None
  repo_file = open(repo_file_path, 'r')
  repository_path = repo_file.read()
  repo_file.close()
  return repository_path



# Run CLI options
# argument is parsed options
def run_tuf_cli_parsed_option(options):

  # Initializes a new repository.
  if options.REPOSITORY_PATH is not None:
    # write repository absolute path to the .tuf_repo_path file
    write_repo_path_to_file(options.REPOSITORY_PATH)

    # Create a new Repository object that holds the file path to the TUF repository
    # and the four top-level role objects (Root, Targets, Snapshot, Timestamp).
    # Metadata files are created when repository.writeall() or repository.write()
    # are called.  The repository directory is created if it does not exist.  You
    # may see log messages indicating any directories created.
    repository = create_new_repository(options.REPOSITORY_PATH)

    # The Repository instance, 'repository', initially contains top-level Metadata
    # objects.  Add one of the public keys, to the root role. Metadata is
    # considered valid if it is signed by the public key's corresponding private key.
    public_root_key = import_rsa_publickey_from_file("keystore/root_key.pub")
    repository.root.add_verification_key(public_root_key)

    # The threshold of each role defaults to 1. Maintainers may change the
    # threshold value, but repository_tool.py validates thresholds and warns
    # users. Set the threshold of the root role to 2, which means the root metadata
    # file is considered valid if it's signed by at least two valid keys.
    # We also load the second private key, which hasn't been imported yet.
    repository.root.threshold = 2
    private_root_key = import_rsa_privatekey_from_file("keystore/root_key")

    # Load the root signing keys to the repository, which writeall() or write()
    # (write multiple roles, or a single role, to disk) use to sign the root
    # metadata.
    repository.root.load_signing_key(private_root_key)

    # Print the roles that are "dirty" (i.e., that have not been written to
    # disk or have changed. Root should be dirty because verification keys
    # have been added, private keys loaded, etc.)
    repository.dirty_roles()
    # The status() function also prints the next role that needs editing.
    repository.status()


  # Generate RSA key.
  if options.RSA_KEY_PASS is not None:
   # The following function creates an RSA key pair, where the private key
   # is saved to "keystore/root_key" and the public key to "keystore/root_key.pub"
   # (both saved to the current working directory).  The 'keystore' directory can
   # be manually created in the current directory to store the keys created in
   # these examples. If 'keystore' directory does not exist, it will be created.
    generate_and_write_rsa_keypair("keystore/root_key", bits=2048,
                                   password=options.RSA_KEY_PASS)
    # TODO Ask Vlad
    #generate_and_write_rsa_keypair("keystore/root_key2")


  # Generate Ed25519 key.
  if options.ED25519_KEY_PASS is not None:
    # Generate and write an Ed25519 key pair. The private key is saved encrypted.
    # A 'password' argument may be supplied, otherwise a prompt is presented.
    generate_and_write_ed25519_keypair("keystore/root_key",
                                       password=options.ED25519_KEY_PASS)


  # Import an existing RSA public key.
  if options.RSA_PUBLIC_KEY_FILE is not None:
    import_rsa_publickey_from_file(options.RSA_PUBLIC_KEY_FILE)


  # Import an existing RSA private key.
  if options.RSA_PRIVATE_KEY_FILE is not None:
    # Importing a private key requires a  password, whereas importing a public
    # key does not.
    import_rsa_privatekey_from_file(options.RSA_PRIVATE_KEY_FILE)


  # Import an existing ED25519 public key.
  if options.ED25519_PUBLIC_KEY_FILE is not None:
    import_ed25519_publickey_from_file(options.ED25519_PUBLIC_KEY_FILE)


  # Import an existing ED25519 private key.
  if options.ED25519_PRIVATE_KEY_FILE is not None:
    import_ed25519_privatekey_from_file(options.ED25519_PRIVATE_KEY_FILE)


  # Create Timestamp, Snapshot and Targets.
  if options.TST is not None:
    # TODO implement
    print options.TST


  # Add Target Files.
  if options.ADD_TARGET_FILES is not None:
    # get repository path
    repo_path = read_repo_path_from_file() + "/"
    # load repository
    repository = load_repository(repo_path)
    # get_filepaths_in_directory() returns a list of file paths in a directory.
    # It can also return files in sub-directories if 'recursive_walk' is True.
    list_of_targets = repository.get_filepaths_in_directory(options.ADD_TARGET_FILES,
                                                            recursive_walk=False,
                                                            followlinks=True)

    # Note: Since we set the 'recursive_walk' argument to false, the 'myproject'
    # sub-directory is excluded from 'list_of_targets'.
    print list_of_targets

    # Add the list of target paths to the metadata of the top-level Targets role.
    # Any target file paths that might already exist are NOT replaced.
    # add_targets() does not create or move target files on the file system.  Any
    # target paths added to a role must fall under the expected targets directory,
    # otherwise an exception is raised.
    repository.targets.add_targets(list_of_targets)

    # The private keys of roles affected by the changes above must now be
    # imported and loaded. targets.json must be signed because a target file was
    # added to its metadata.

    # The private key of the updated targets metadata must be loaded before it can
    # be signed and written (Note the load_repository() call above).
    private_targets_key = import_rsa_privatekey_from_file("keystore/targets_key")
    repository.targets.load_signing_key(private_targets_key)

    # Due to the load_repository() and new versions of metadata, we must also load
    # the private keys of Snapshot and Timestamp to generate a valid set of metadata.
    private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key")
    repository.snapshot.load_signing_key(private_snapshot_key)
    private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
    repository.timestamp.load_signing_key(private_timestamp_key)

    # Which roles are dirty?
    repository.dirty_roles()
    # Generate new versions of the modified top-level metadata
    # (targets, snapshot, and timestamp).
    repository.writeall()


  # Remove Target File.
  if options.DEL_TARGET_FILE is not None:
    # get repository path
    repo_path = read_repo_path_from_file() + "/"
    # load repository
    repository = load_repository(repo_path)

    # Remove a target file listed in the "targets" metadata.
    # The target file is not actually deleted from the file system.
    repository.targets.remove_target(DEL_TARGET_FILE)

    # repository.writeall() writes any required metadata files (e.g., if
    # targets.json is updated, snapshot.json and timestamp.json are also written
    # to disk), updates those that have changed, and any that need updating to make
    # a new "snapshot" (new snapshot.json and timestamp.json).
    repository.writeall()



# Parse repository management tools' command line arguments.
def parse_tuf_cli():

  parser = OptionParser()
  # Initializes a new repository, CLI option.
  parser.add_option("--init",  
                    help = "Specify the repository path",
                    type = "string",
                    dest = "REPOSITORY_PATH")

  # Generate RSA key, CLI option.
  parser.add_option("--gen_rsa_key",
                    help = "Generate RSA key, specify password",
                    type = "string",
                    dest = "RSA_KEY_PASS")

  # Generate Ed25519 key, CLI option.
  parser.add_option("--gen_ed25519_key",
                    help = "Generate Ed25519 key, specify password",
                    type = "string",
                    dest = "ED25519_KEY_PASS")

  # Import RSA public key, CLI option.
  parser.add_option("--import_rsa_public_key",
                    help = ("Import RSA public key, "
                            "specify the RSA public key file"),
                    type = "string",
                    dest = "RSA_PUBLIC_KEY_FILE")

  # Import RSA private key, CLI option.
  parser.add_option("--import_rsa_private_key",
                    help = ("Import RSA private key, " 
                            "specify the RSA private key file"),
                    type = "string",
                    dest = "RSA_PRIVATE_KEY_FILE")

  # Import ED25519 public key, CLI option.
  parser.add_option("--import_ed25519_public_key",
                    help = ("Import ED25519 public key, "
                            "specify the ed25519 public key file"),
                    type = "string",
                    dest = "ED25519_PUBLIC_KEY_FILE")

  # Import ED25519 private key, CLI option.
  parser.add_option("--import_ed25519_private_key",
                    help = ("Import ED25519 private key, "
                            "specify the ed25519 private key file"),
                    type = "string",
                    dest = "ED25519_PRIVATE_KEY_FILE")

  # Create Timestamp, Snapshot and Targets, CLI option.
  parser.add_option("--tst",
                    help = ("Create Timestamp, Snapshot and Targets, "
                            "specify year, month, week and day. "
                            "Format: year/month/week/day"),
                    type = "string",
                    dest = "TST")

  # Add Target Files, CLI option.
  parser.add_option("--add_target_files",
                    help = ("Add Target Files, specify target files' path."),
                    type = "string",
                    dest = "ADD_TARGET_FILES")

  # Remove Target File, CLI option.
  parser.add_option("--del_target_file",
                    help = ("Remove Target File, specify target file's path."),
                    type = "string",
                    dest = "DEL_TARGET_FILE")

  # Parse argument value.
  (options, args) = parser.parse_args()
  run_tuf_cli_parsed_option(options)


# MAIN
if __name__ == "__main__":
  parse_tuf_cli()
