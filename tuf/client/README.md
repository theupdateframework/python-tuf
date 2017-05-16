# updater.py
**updater.py** is intended as the only TUF module that software update
systems need to utilize for a low-level integration.  It provides a single
class representing an updater that includes methods to download, install, and
verify metadata or target files in a secure manner.  Importing
**tuf.client.updater** and instantiating its main class is all that is
required by the client prior to a TUF update request.  The importation and
instantiation steps allow TUF to load all of the required metadata files
and set the repository mirror information.

The **tuf.repository_tool** module can be used to create a TUF repository.  See
[tuf/README](../README.md) for more information on creating TUF repositories.

The **tuf.interposition** package can also assist in integrating TUF with a
software updater.  See [tuf/interposition/README](../interposition/README.md)
for more information on interposing Python urllib calls with TUF.


## Overview of the Update Process

1. The software update system instructs TUF to check for updates.

2. TUF downloads and verifies timestamp.json.

3. If timestamp.json indicates that snapshot.json has changed, TUF downloads and
verifies snapshot.json.

4. TUF determines which metadata files listed in snapshot.json differ from those
described in the last snapshot.json that TUF has seen.  If root.json has changed,
the update process starts over using the new root.json.

5. TUF provides the software update system with a list of available files
according to targets.json.

6. The software update system instructs TUF to download a specific target
file.

7. TUF downloads and verifies the file and then makes the file available to
the software update system.


If at any point in the above procedure there is a problem (i.e., if unexpired,
signed, valid metadata cannot be retrieved from the repository), the Root file
is downloaded and the process is retried once more (and only once to avoid an
infinite loop).  Optionally, the software update system using the framework
can decide how to proceed rather than automatically downloading a new Root file.


## Example Client
### Refresh TUF Metadata and Download Target Files
```Python
# The client first imports the 'updater.py' module, the only module the
# client is required to import.  The client will utilize a single class
# from this module.
import tuf.client.updater

# The only other module the client interacts with is 'settings'.  The
# client accesses this module solely to set the repository directory.
# This directory will hold the files downloaded from a remote repository.
settings.repository_directory = 'path/to/local_repository'

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

# The client calls the refresh() method to ensure it has the latest
# copies of the top-level metadata files (i.e., Root, Targets, Snapshot,
# Timestamp).
updater.refresh()

# The target file information of all the repository targets is determined next.
# Since all_targets() downloads the target files of every role, all role
# metadata is updated.
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
# tracked. For example, a target file from a previous snapshot that has since
# been removed on the remote repository.
updater.remove_obsolete_targets(destination_directory)
```

### Download Target Files of a Role
```Python
# Example demonstrating an update that only downloads the targets of            
# a specific role (i.e., 'targets/django').                                     

# Refresh the metadata of the top-level roles (i.e., Root, Targets, Snapshot, Timestamp).
updater.refresh()

# Update the 'targets/django' role, and determine the target files that have changed.
# targets_of_role() refreshes the minimum metadata needed to download the target files
# of the specified role (e.g., R1->R4->R5, where R2 and R3 are excluded).
targets_of_django = updater.targets_of_role('targets/django')                     
updated_targets = updater.updated_targets(targets_of_django, destination_directory)
                                                                                 
for target in updated_targets:                                                  
  updater.download_target(target, destination_directory)                        
```

### Download Specific Target File
```Python
# Example demonstrating an update that downloads a specific target.             

# Refresh the metadata of the top-level roles (i.e., Root, Targets, Snapshot, Timestamp).           
updater.refresh()

# get_one_valid_targetinfo() updates role metadata when required.  In other
# words, if the client doesn't possess the metadata that lists 'LICENSE.txt',
# get_one_valid_targetinfo() will try to fetch / update it.
target = updater.get_one_valid_targetinfo('LICENSE.txt')
updated_target = updater.updated_targets([target], destination_directory)
                                                                                 
for target in updated_target:                                                   
  updater.download_target(target, destination_directory)
  # Client code here may also reference target information (including 'custom')
  # by directly accessing the dictionary entries of the target.  The 'custom'
  # entry is additional file information explicitly set by the remote repository.
  target_path = target['filepath']
  target_length = target['fileinfo']['length']
  target_hashes = target['fileinfo']['hashes']
  target_custom_data = target['fileinfo']['custom']
```

### A Simple Integration Example with basic_client.py
``` Bash
# Assume a simple TUF repository has been setup with 'tuf.repository_tool.py'.
$ basic_client.py --repo http://localhost:8001

# Metadata and target files are silently updated.  An exception is only raised if an error,
# or attack, is detected.  Inspect 'tuf.log' for the outcome of the update process.

$ cat tuf.log
[2013-12-16 16:17:05,267 UTC] [tuf.download] [INFO][_download_file:726@download.py]
Downloading: http://localhost:8001/metadata/timestamp.json

[2013-12-16 16:17:05,269 UTC] [tuf.download] [WARNING][_check_content_length:589@download.py]
reported_length (545) < required_length (2048)

[2013-12-16 16:17:05,269 UTC] [tuf.download] [WARNING][_check_downloaded_length:656@download.py]
Downloaded 545 bytes, but expected 2048 bytes. There is a difference of 1503 bytes!

[2013-12-16 16:17:05,611 UTC] [tuf.download] [INFO][_download_file:726@download.py]
Downloading: http://localhost:8001/metadata/snapshot.json

[2013-12-16 16:17:05,612 UTC] [tuf.client.updater] [INFO][_check_hashes:636@updater.py]
The file's sha256 hash is correct: 782675fadd650eeb2926d33c401b5896caacf4fd6766498baf2bce2f3b739db4

[2013-12-16 16:17:05,951 UTC] [tuf.download] [INFO][_download_file:726@download.py]
Downloading: http://localhost:8001/metadata/targets.json

[2013-12-16 16:17:05,952 UTC] [tuf.client.updater] [INFO][_check_hashes:636@updater.py]
The file's sha256 hash is correct: a5019c28a1595c43a14cad2b6252c4d1db472dd6412a9204181ad6d61b1dd69a

[2013-12-16 16:17:06,299 UTC] [tuf.download] [INFO][_download_file:726@download.py]
Downloading: http://localhost:8001/targets/file1.txt

[2013-12-16 16:17:06,303 UTC] [tuf.client.updater] [INFO][_check_hashes:636@updater.py]
The file's sha256 hash is correct: ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8
