"""
<Program Name>
  example_client.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 2012.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Example script demonstrating custom python code a software updater
  utilizing The Update Framework may write to securely update files.
  The 'basic_client.py' script can be used on the command-line to perform
  an update that will download and update all available targets; writing
  custom code is not required with 'basic_client.py'.
  
  The custom examples below demonstrate:
  (1) updating all targets
  (2) updating all the targets of a specified role
  (3) updating a specific target explicitly named.

  It assumes a server is listening on 'http://localhost:8001'.  One can be
  started by navigating to the 'examples/repository/' and starting:
  $ python -m SimpleHTTPServer 8001
"""

import logging

import tuf.client.updater

# Uncomment the line below to enable printing of debugging information.
tuf.log.set_log_level(logging.INFO)

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
all_targets = updater.all_targets()
updated_targets = updater.updated_targets(all_targets, destination_directory)

# Download each of these updated targets and save them locally.
for target in updated_targets:
  try:
    updater.download_target(target, destination_directory)
  
  except tuf.DownloadError as e:
    pass

# Remove any files from the destination directory that are no longer being
# tracked.
updater.remove_obsolete_targets(destination_directory)



# Example demonstrating an update that only downloads the targets of
# a specific role (i.e., 'targets/project')
updater.refresh()
targets_of_role1 = updater.targets_of_role('targets/project')
updated_targets = updater.updated_targets(targets_of_role1, destination_directory)

for target in updated_targets:
  updater.download_target(target, destination_directory)



# Example demonstrating an update that downloads a specific target.
updater.refresh()
target = updater.target('/file2.txt')
updated_target = updater.updated_targets([target], destination_directory)

for target in updated_target:
  updater.download_target(target, destination_directory)
