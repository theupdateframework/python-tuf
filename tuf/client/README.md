#updater.py
**updater.py** is intended to be the only TUF module that software update
systems need to utilize for a low-level integration.  It provides a single
class representing an updater that includes methods to download, install, and
verify metadata/target files in a secure manner.  Importing **updater.py** and
instantiating its main class is all that is required by the client prior
to a TUF update request.  The importation and instantiation steps allow
TUF to load all of the required metadata files and set the repository mirror
information.

The **tuf.libtuf** module can be used to create a TUF repository.

The **tuf.interposition** package can also assist in integrating TUF with a
software updater.  See **tuf.interposition.README** for more information on
interposing Python urllib calls with TUF.


## Overview of the update process:
1. The software update system instructs TUF to check for updates.

2. TUF downloads and verifies timestamp.txt.

3. If timestamp.txt indicates that release.txt has changed, TUF downloads and
verifies release.txt.

4. TUF determines which metadata files listed in release.txt differ from those
described in the last release.txt that TUF has seen.  If root.txt has changed,
the update process starts over using the new root.txt.

5. TUF provides the software update system with a list of available files
according to targets.txt.

6. The software update system instructs TUF to download a specific target
file.

7. TUF downloads and verifies the file and then makes the file available to
the software update system.


## Example Client 
```Python
# The client first imports the 'updater.py' module, the only module the
# client is required to import.  The client will utilize a single class
# from this module.
import tuf.client.updater

# The only other module the client interacts with is 'tuf.conf'.  The
# client accesses this module solely to set the repository directory.
# This directory will hold the files downloaded from a remote repository.
tuf.conf.repository_directory = 'local-repository'

# Next, the client creates a dictionary object containing the repository
# mirrors.  The client may download content from any one of these mirrors.
# In the example below, a single mirror named 'mirror1' is defined.  The
# mirror is located at 'http://localhost:8001', and all of the metadata
# and targets files can be found in the 'metadata' and 'targets' directory,
# respectively.  If the client wishes to only download target files from
# specific directories on the mirror, the 'confined_target_dirs' field
# should be set.  In the example, the client has chosen '', which is
# interpreted as no confinement.  In other words, the client can download
# targets from any directory or subdirectories.  If the client had chosen
# 'targets1/', they would have been confined to the '/targets/targets1/'
# directory on the 'http://localhost:8001' mirror. 
repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                  'metadata_path': 'metadata',
                                  'targets_path': 'targets',
                                  'confined_target_dirs': ['']}}

# The updater may now be instantiated.  The Updater class of 'updater.py'
# is called with two arguments.  The first argument assigns a name to this
# particular updater and the second argument the repository mirrors defined
# above.
updater = tuf.client.updater.Updater('updater', repository_mirrors)

# The client next calls the refresh() method to ensure it has the latest
# copies of the metadata files.
updater.refresh()

# The target file information for all the repository targets is determined.
targets = updater.all_targets()

# Among these targets, determine the ones that have changed since the client's
# last refresh().  A target is considered updated if it does not exist in
# 'destination_directory' (current directory) or the target located there has
# changed.
destination_directory = '.'
updated_targets = updater.updated_targets(targets, destination_directory)

# Lastly, attempt to download each target among those that have changed.
# The updated target files are saved locally to 'destination_directory'.
for target in updated_targets:
  updater.download_target(target, destination_directory)

# Remove any files from the destination directory that are no longer being
# tracked.
updater.remove_obsolete_targets(destination_directory)
```
