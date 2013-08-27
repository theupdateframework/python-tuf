"""
<Program Name>
  example_integration.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  August 1, 2013

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Example client script outlining custom python code one can write for a
  PyPI+pip+TUF integration.  It aims to demonstrate efficient retrieval
  of a target file and a metadata chain of trust, in a secure manner.
  
  The custom example below demonstrates updating all the targets of a
  specified role (i.e., 'targets/packages/A/Alice.txt').

"""

import logging

import tuf.client.updater

# Uncomment the line below to enable printing of debugging information.
tuf.log.set_log_level(logging.DEBUG)

# Set the local repository directory containing the metadata files.
tuf.conf.repository_directory = '.'

# Set the repository mirrors.  This dictionary is needed by the Updater
# class of updater.py.  The client will download metadata and target
# files from any one of these mirrors.
repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                  'metadata_path': 'metadata',
                                  'targets_path': 'targets',
                                  'confined_target_dirs': ['']}}

# Create the Upater object using the updater name 'tuf-example'
# and the repository mirrors defined above.
updater = tuf.client.updater.Updater('tuf-example', repository_mirrors)

# Set the local destination directory to save the target files.
destination_directory = './targets'

# Refresh the repository's top-level roles, store the target information for
# all the targets of the 'Alice' project, and determine which of these targets
# have been updated.  First, refresh top-level roles...
updater.refresh()

# The 'release.txt' file may be inspected to retreive our desired role, or
# a dictionary that links project names to project roles.
# For example: {'Alice': 'targets/packages/A/Alice'}
alice_role = 'targets/packages/A/Alice'

# Before we can download the metadata for 'alice_role', the chain of trust
# must be built.  At the moment, the client has only downloaded/updated
# the metadata for the top-level roles.
# Download: 'targets/packages.txt', 'targets/packages/A.txt',
# 'targets/packages/A/Alice.txt'.  In other words, we only fetch the minimum
# required to get a list of targets that the 'Alice' project
# has signed.  Calling updater.all_targets() or updater.target() causes an 
# update of all the metadata on the repository, which might be inefficient
# for a repository like PyPI.
updater.refresh_targets_metadata_chain(alice_role)
targets_of_alice = updater.targets_of_role(alice_role)
updated_targets = updater.updated_targets(targets_of_alice, destination_directory)

# The pip software updater might request multiple targets in one update
# cycle (i.e.,
# $ pip install Alice
# fetches 'simple/Alice/index.html', 'alice-v0.1.tar.gz', ...)
# As a simple example here, download a single target file arbitrarily
# chosen, and save it locally.
for updated_target in updated_targets:
  if updated_target['filepath'] == 'packages/A/Alice/alice-v0.1.tar.gz': 
    updater.download_target(updated_target, destination_directory)

# Remove any files from the destination directory that are no longer being
# tracked.
updater.remove_obsolete_targets(destination_directory)
