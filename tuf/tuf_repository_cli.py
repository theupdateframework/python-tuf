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
  Provide a CLI to the Repository Management Tools.
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
    write_repo_path_to_file(options.REPOSITORY_PATH)
    repository = create_new_repository(options.REPOSITORY_PATH)

    public_root_key = import_rsa_publickey_from_file("keystore/root_key.pub")
    repository.root.add_verification_key(public_root_key)

    private_root_key = import_rsa_privatekey_from_file("keystore/root_key")
    repository.root.load_signing_key(private_root_key)

    repository.dirty_roles()
    repository.status()

  # Generate RSA key.
  if options.RSA_KEY_PASS is not None:
    generate_and_write_rsa_keypair("keystore/root_key", bits=2048,
                                   password=options.RSA_KEY_PASS)
    # TODO Ask Vlad
    #generate_and_write_rsa_keypair("keystore/root_key2")

  # Generate Ed25519 key.
  if options.ED25519_KEY_PASS is not None:
    generate_and_write_ed25519_keypair("keystore/root_key",
                                       password=options.ED25519_KEY_PASS)


  # Import RSA public key.
  if options.RSA_PUBLIC_KEY_FILE is not None:
    import_rsa_publickey_from_file(options.RSA_PUBLIC_KEY_FILE)


  # Import RSA private key.
  if options.RSA_PRIVATE_KEY_FILE is not None:
    import_rsa_privatekey_from_file(options.RSA_PRIVATE_KEY_FILE)


  # Import ED25519 public key.
  if options.ED25519_PUBLIC_KEY_FILE is not None:
    import_ed25519_publickey_from_file(options.ED25519_PUBLIC_KEY_FILE)


  # Import ED25519 private key.
  if options.ED25519_PRIVATE_KEY_FILE is not None:
    import_ed25519_privatekey_from_file(options.ED25519_PRIVATE_KEY_FILE)



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

  # Parse argument value.
  (options, args) = parser.parse_args()
  run_tuf_cli_parsed_option(options)


# MAIN
if __name__ == "__main__":
  parse_tuf_cli()
