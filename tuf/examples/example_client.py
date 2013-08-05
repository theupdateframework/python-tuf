"""
<Program Name>
  simple_pip_integration.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  August 1, 2013

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Example client script demonstrating custom python code one can write for a
  PyPI+pip+TUF integration.
  
  The custom example below demonstrates updating all the targets of a
  specified role (i.e., 'targets/

"""

import logging

import tuf.client.updater

# Uncomment the line below to enable printing of debugging information.
#tuf.log.set_log_level(logging.DEBUG)

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
# all the targets tracked, and determine which of these targets have been
# updated.
updater.refresh()

#  
updater.refresh_targets_metadata_chain(
all_targets = updater.all_targets()
updated_targets = updater.updated_targets(all_targets, destination_directory)

# Download each of these updated targets and save them locally.
for target in updated_targets:
  try:
    updater.download_target(target, destination_directory)
  except tuf.DownloadError, e:
    pass

# Remove any files from the destination directory that are no longer being
# tracked.
updater.remove_obsolete_targets(destination_directory)
