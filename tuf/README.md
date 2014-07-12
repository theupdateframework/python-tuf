# Repository Management #

## Table of Contents ##
- [How to Create and Modify a Basic TUF Repository](#how-to-create-and-modify-a-tuf-repository)
  - [Overview](#overview)
  - [Purpose](#purpose)
  - [Keys](#keys)
    - [Create RSA Keys](#create-rsa-keys)
    - [Import RSA Keys](#import-rsa-keys)
    - [Create and Import ED25519 Keys](#create-and-import-ed25519-keys)
  - [Create Top-level Metadata](#create-top-level-metadata)
    - [Create Root](#create-root)
    - [Create Timestamp, Snapshot, Targets](#create-timestamp-snapshot-targets)
  - [Targets](#targets)
    - [Add Target Files](#add-target-files)
    - [Remove Target Files](#remove-target-files)
  - [Delegations](#delegations)
    - [Revoke Delegated Role](#revoke-delegated-role)
  - [Wrap-up](#wrap-up)
- [Delegate to Hashed Bins](#delegate-to-hashed-bins)
- [Consistent Snapshots](#consistent-snapshots)


## How to Create and Modify a TUF Repository ##

### Overview ###
Metadata, updater.py outline, tools.

The [repository tool](repository_tool.py) is not used in TUF integrations.  The
[tuf.interposition](interposition/README.md) package and
[tuf.client.updater](client/README.md) module assist in integrating TUF with a
software updater.

A [diagram](../docs/images/repository_tool-diagram.png) is available that lists
the methods and functions of [repository_tool.py](repository_tool.py)

Documentation for setting up a TUF client and performing an update is available
[here](client_setup_and_repository_example.md).


### Purpose ###

The [repository_tool.py](repository_tool.py) module can be used to create a
TUF repository.  It may either be imported into a Python module or used with the
Python interpreter in interactive mode.

```Bash
$ python
Python 2.7.3 (default, Sep 26 2013, 20:08:41) 
[GCC 4.6.3] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from tuf.repository_tool import *
>>> repository = load_repository("/path/to/repository")
```
The repository tool requires additional cryptographic libraries and may be
installed as follows:
```Bash
$ pip install tuf[tools]
```

### Keys ###
Say a bit about key format, key types, how to store.

#### Create RSA Keys ####
```python
>>> from tuf.repository_tool import *

# Generate and write the first of two root keys for the TUF repository.
# The following function creates an RSA key pair, where the private key is saved to
# "/path/to/root_key" and the public key to "/path/to/root_key.pub".
>>> generate_and_write_rsa_keypair("/path/to/root_key", bits=2048, password="password")

# If the key length is unspecified, it defaults to 3072 bits. A length of less 
# than 2048 bits raises an exception. A password may be supplied as an 
# argument, otherwise a user prompt is presented.
>>> generate_and_write_rsa_keypair("/path/to/root_key2")
Enter a password for the RSA key:
Confirm:
```
The following four key files should now exist:

1.  **root_key**
2.  **root_key.pub**
3.  **root_key2**
4.  **root_key2.pub**

### Import RSA Keys ###
```python
>>> from tuf.repository_tool import *

# Import an existing public key.
>>> public_root_key = import_rsa_publickey_from_file("/path/to/root_key.pub")

# Import an existing private key.  Importing a private key requires a password, whereas
# importing a public key does not.
>>> private_root_key = import_rsa_privatekey_from_file("/path/to/root_key")
Enter a password for the encrypted RSA key:
```
`import_rsa_privatekey_from_file()` raises a `tuf.CryptoError` exception if the
key / password is invalid.

### Create and Import ED25519 Keys ###
```Python
>>> from tuf.repository_tool import *

# Generate and write an ed25519 key pair.  The private key is saved encrypted.
# A 'password' argument may be supplied, otherwise a prompt is presented.
>>> generate_and_write_ed25519_keypair('/path/to/ed25519_key')
Enter a password for the ED25519 key: 
Confirm:

# Import the ed25519 public key just created . . .
>>> public_ed25519_key = import_ed25519_publickey_from_file('/path/to/ed25519_key.pub')

# and its corresponding private key.
>>> private_ed25519_key = import_ed25519_privatekey_from_file('/path/to/ed25519_key')
Enter a password for the encrypted ED25519 key: 
```

### Create Top-level Metadata ###
The [metadata document](../METADATA.md) outlines the JSON metadata files that
must exist on a TUF repository.  The following sub-sections provide the
`repository_tool.py` calls repository maintainers may issue to generate the
required roles.  The top-level roles to be created are `root`, `timestamp`,
`snapshot`, and `target`.

We begin with `root`, the root of trust that specifies the public keys of the 
top-level roles, including itself. 


#### Create Root ####
```python
# Continuing from the previous section . . .

# Create a new Repository object that holds the file path to the repository and the four
# top-level role objects (Root, Targets, Snapshot, Timestamp). Metadata files are created when
# repository.write() is called.  The repository directory is created if it does not exist.
>>> repository = create_new_repository("/path/to/repository/")

# The Repository instance, 'repository', initially contains top-level Metadata objects.
# Add one of the public keys, created in the previous section, to the root role.  Metadata is
# considered valid if it is signed by the public key's corresponding private key.
>>> repository.root.add_verification_key(public_root_key)

# Role keys (i.e., the key's keyid) may be queried.  Other attributes include: signing_keys, version,
# signatures, expiration, threshold, delegations (Targets role), and compressions.
>>> repository.root.keys
['b23514431a53676595922e955c2d547293da4a7917e3ca243a175e72bbf718df']

# Add a second public key to the root role.  Although previously generated and saved to a file,
# the second public key must be imported before it can added to a role.
>>> public_root_key2 = import_rsa_publickey_from_file("/path/to/root_key2.pub")
>>> repository.root.add_verification_key(public_root_key2)

# Threshold of each role defaults to 1.   Users may change the threshold value, but repository_tool.py
# validates thresholds and warns users.  Set the threshold of the root role to 2,
# which means the root metadata file is considered valid if it contains at least two valid 
# signatures.
>>> repository.root.threshold = 2
>>> private_root_key2 = import_rsa_privatekey_from_file("/path/to/root_key2", password="password")

# Load the root signing keys to the repository, which write() uses to sign the root metadata.
# The load_signing_key() method SHOULD warn when the key is NOT explicitly allowed to
# sign for it.
>>> repository.root.load_signing_key(private_root_key)
>>> repository.root.load_signing_key(private_root_key2)

# Print the number of valid signatures and public / private keys of the
# repository's metadata.
>>> repository.status()
'root' role contains 2 / 2 signatures.
'targets' role contains 0 / 1 public keys.

>>> try:
...   repository.write()

# An exception is raised here by write() because the other top-level roles (targets, snapshot,
# and timestamp) have not been configured with keys.  Another option is to call
# repository.write_partial() and generate metadata that may contain an invalid threshold of
# signatures, required public keys, etc.  write_partial() allows multiple repository maintainers to
# independently sign metadata and generate them separately.  load_repository() can load partially
# written metadata.
>>> except tuf.UnsignedMetadataError, e:
...   print e 
Not enough signatures for '/path/to/repository/metadata.staged/targets.json'

# In the next section, update the other top-level roles and create a repository with valid metadata.
```

#### Create Timestamp, Snapshot, Targets
Now that `root.json` has been set, the other top-level roles may be created.
The signing keys added to these roles must correspond to the public keys
specified by the root.  

On the client side, `root.json` must always exist.  The other top-level roles,
created next, are requested by repository clients in (Timestamp -> Snapshot ->
Root -> Targets) order to ensure required metadata is downloaded in a secure
manner.

```python
# Continuing from the previous section . . .
>>> import datetime

# Generate keys for the remaining top-level roles.  The root keys have been set above.
# The password argument may be omitted if a password prompt is needed. 
>>> generate_and_write_rsa_keypair("/path/to/targets_key", password="password")
>>> generate_and_write_rsa_keypair("/path/to/snapshot_key", password="password")
>>> generate_and_write_rsa_keypair("/path/to/timestamp_key", password="password")

# Add the public keys of the remaining top-level roles.
>>> repository.targets.add_verification_key(import_rsa_publickey_from_file("/path/to/targets_key.pub"))
>>> repository.snapshot.add_verification_key(import_rsa_publickey_from_file("/path/to/snapshot_key.pub"))
>>> repository.timestamp.add_verification_key(import_rsa_publickey_from_file("/path/to/timestamp_key.pub"))

# Import the signing keys of the remaining top-level roles.  Prompt for passwords.
>>> private_targets_key = import_rsa_privatekey_from_file("/path/to/targets_key")
Enter a password for the encrypted RSA key:

>>> private_snapshot_key = import_rsa_privatekey_from_file("/path/to/snapshot_key")
Enter a password for the encrypted RSA key:

>>> private_timestamp_key = import_rsa_privatekey_from_file("/path/to/timestamp_key")
Enter a password for the encrypted RSA key:

# Load the signing keys of the remaining roles so that valid signatures are generated when
# repository.write() is called.
>>> repository.targets.load_signing_key(private_targets_key)
>>> repository.snapshot.load_signing_key(private_snapshot_key)
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Optionally set the expiration date of the timestamp role.  By default, roles are set to expire
# as follows:  root(1 year), targets(3 months), snapshot(1 week), timestamp(1 day).
>>> repository.timestamp.expiration = datetime.datetime(2014, 10, 28, 12, 8)

# Metadata files may also be compressed.  Only "gz" (gzip) is currently supported.
>>> repository.targets.compressions = ["gz"]
>>> repository.snapshot.compressions = ["gz"]

# Write all metadata to "/path/to/repository/metadata.staged/".  The common case is to crawl the
# filesystem for all delegated roles in "/path/to/repository/metadata.staged/targets/".
>>> repository.write()
```

### Targets ###
TUF verifies target files by including their length, hash(es),
and filepath in metadata.  The filepaths are relative to a `targets/` directory
on the repository.  A TUF client can download a target file by first updating 
the latest copy of metadata (and thus available targets), verifying that their
length and hashes are valid, and then saving them locally to complete the
process.

In this section, the target files intended for clients are added to a repository
and listed in `targets.json` metadata.

#### Add Target Files ####

The repository maintainer adds target files to roles (e.g., `targets`,
`targets/unclaimed`) by specifying target paths.  Files at these target paths
must exist before the repository tool can generate and add their (hashes,
lengths, filepath) to metadata.

The actual target files are added first to the `targets/` directory of the
repository.

```Bash
# Create and save target files to the targets directory of the repository.
$ cd /path/to/repository/targets/
$ echo 'file1' > file1.txt
$ echo 'file2' > file2.txt
$ echo 'file3' > file3.txt
$ mkdir django; echo 'file4' > django/file4.txt
```

With the target files available on the `targets/` directory of the repository,
the `add_targets()` method of a Targets role can be called to add the target to
metadata.

```python
>>> from tuf.repository_tool import *
>>> import os

# Load the repository created in the previous section.  This repository so far
# contains metadata for the top-level roles, but no targets are yet listed in
# the metadata.
>>> repository = load_repository("/path/to/repository/")

# get_filepaths_in_directory() returns a list of file paths in a directory.  It can also return
# files in sub-directories if 'recursive_walk' is True.
>>> list_of_targets = repository.get_filepaths_in_directory("/path/to/repository/targets/",
                                                        recursive_walk=False, followlinks=True) 

# Add the list of target paths to the metadata of the Targets role.  Any target file paths
# that may already exist are NOT replaced.  add_targets() does not create or move
# target files on the file system.  Any target paths added to a role must be
# relative to the targets directory, otherwise an exception is raised.
>>> repository.targets.add_targets(list_of_targets)

# Individual target files may also be added to roles, including custom data about the target.
# In the example below, file permissions of the target (octal number specifying file
# access for owner, group, others (e.g., 0755) is added alongside the default fileinfo.
# All target objects in metadata include the target's filepath, hash, and length.
>>> target3_filepath = "/path/to/repository/targets/file3.txt"
>>> octal_file_permissions = oct(os.stat(target3_filepath).st_mode)[4:]
>>> custom_file_permissions = {'file_permissions': octal_file_permissions}
>>> repository.targets.add_target(target3_filepath, custom_file_permissions)
```

The private keys of roles affected by the changes above must now be imported and
loaded.  `targets.json` must be signed because a target file was added to its
metadata.  `snapshot.json` keys must be loaded and its metadata signed because
`targets.json` has changed.  Similarly, since `snapshot.json` has changed, the
`timestamp.json` role must also be signed.

```Python
# The private key of the updated targets metadata must be loaded before it can be signed and
# written (Note the load_repository() call above).
>>> private_targets_key =  import_rsa_privatekey_from_file("/path/to/targets_key")
Enter a password for the encrypted RSA key:

>>> repository.targets.load_signing_key(private_targets_key)

# Due to the load_repository() and new versions of metadata, we must also load
# the private keys of Snapshot and Timestamp to generate a valid set of metadata.
>>> private_snapshot_key = import_rsa_privatekey_from_file("/path/to/snapshot_key")
Enter a password for the encrypted RSA key:
>>> repository.snapshot.load_signing_key(private_snapshot_key)

>>> private_timestamp_key = import_rsa_privatekey_from_file("/path/to/timestamp_key")
Enter a password for the encrypted RSA key:
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Generate new versions of all the top-level metadata.
>>> repository.write()
```

#### Remove Target Files ####

Target files previously added to roles may also be removed.  Removing a target
file requires first removing the target from a role and then writing the
new metadata to disk.
```python
# Continuing from the previous section . . .

# Remove a target file listed in the "targets" metadata.  The target file is not actually deleted
# from the file system.
>>> repository.targets.remove_target("/path/to/repository/targets/file3.txt")

# repository.write() creates any new metadata files, updates those that have changed, and any that
# need updating to make a new "snapshot" (new snapshot.json and timestamp.json).
>>> repository.write()
```

### Delegations ###
Overview of delegations.  Why are they needed? Simple example.

```python
# Continuing from the previous section . . .

# Generate a key for a new delegated role named "unclaimed".
>>> generate_and_write_rsa_keypair("/path/to/unclaimed_key", bits=2048, password="password")
>>> public_unclaimed_key = import_rsa_publickey_from_file("/path/to/unclaimed_key.pub")

# Make a delegation from "targets" to "targets/unclaimed", initially containing zero targets.
# The delegated role’s full name is not expected.
# delegate(rolename, list_of_public_keys, list_of_file_paths, threshold,
#          restricted_paths, path_hash_prefixes)
>>> repository.targets.delegate("unclaimed", [public_unclaimed_key], [])

# Load the private key of "targets/unclaimed" so that signatures are later added and valid
# metadata is created.
>>> private_unclaimed_key = import_rsa_privatekey_from_file("/path/to/unclaimed_key")
Enter a password for the encrypted RSA key:

>>> repository.targets(unclaimed).load_signing_key(private_unclaimed_key)

# Update an attribute of the unclaimed role.
>>> repository.targets('unclaimed').version = 2

# Delegations may also be nested.  Create the delegated role "targets/unclaimed/django",
# where it initially contains zero targets and future targets are restricted to a
# particular directory.
>>> repository.targets('unclaimed').delegate("django", [public_unclaimed_key], [],
                                         restricted_paths=["/path/to/repository/targets/django/"])
>>> repository.targets('unclaimed')('django').load_signing_key(private_unclaimed_key)
>>> repository.targets('unclaimed')('django').add_target("/path/to/repository/targets/django/file4.txt")
>>> repository.targets('unclaimed')('django').compressions = ["gz"]

#  Write the metadata of "targets/unclaimed", "targets/unclaimed/django", root, targets, snapshot,
# and timestamp.
>>> repository.write()
```

#### Revoke Delegated Role ####
```python
# Continuing from the previous section . . .

# Create a delegated role that will be revoked in the next step.
>>> repository.targets('unclaimed').delegate("flask", [public_unclaimed_key], [])

# Revoke "targets/unclaimed/flask" and write the metadata of all remaining roles.
>>> repository.targets('unclaimed').revoke("flask")
>>> repository.write()
```

#### Wrap-up ####

In summary, the five steps a repository maintainer follows to create a basic TUF
repository are:

1.  Generate repository directory that contains TUF metadata and the target files.
2.  Create top-level roles (`root.json`, `snapshot.json`, `targets.json`, and `timestamp.json`.) 
3.  Add target files to the `targets` role.
4.  Optionally, create delegated roles to distribute target files.
5.  Write the changes.

The repository tool saves repository changes to a `metadata.staged` directory.
Repository maintainers may push the final changes to the "live" repository by
copying the staged directory to its destination. 
```Bash
# Copy the staged metadata directory changes to the live repository.
$ cp -r "/path/to/repository/metadata.staged/" "/path/to/repository/metadata/"
```

## Delegate to Hashed Bins ##
Why use hashed bin delegations?

For software update systems with a large number of target files, delegating to
hashed bins (a special type of delegated role) might be an easier alternative to
manually performing the delegations.  How many target files should each delegated
role contain?  How will these delegations affect the number of metadata that
clients must additionally download in a typical update?  Hashed bin delegations
is availabe to integrators that rather not deal with the answers to these
questions.

A large number of target files may be distributed to multiple hashed bins with
`delegate_hashed_bins()`.  The metadata files of delegated roles will be nearly equal in size
(i.e., target file paths are uniformly distributed by calculating the target filepath's
digest and determining which bin it should reside in.  The updater client will use
"lazy bin walk" to find a target file's hashed bin destination.  This method is intended
for repositories with a large number of target files, a way of easily distributing and
managing the metadata that lists the targets, and minimizing the number of metadata files
(and size) downloaded by the client.

The `delegate_hashed_bins()` method has the following form:
```Python
delegate_hashed_bins(list_of_targets, keys_of_hashed_bins, number_of_bins)
```

A complete example of retrieving target paths to add to hashed bins,
performing the hashed bin delegations, signing them, and finally adding
restricted paths for some role is provided next.
```Python
# Get a list of target paths for the hashed bins.
>>> targets = \
  repository.get_filepaths_in_directory('/path/to/repository/targets/django', recursive_walk=True)
>>> repository.targets('unclaimed')('django').delegate_hashed_bins(targets, [public_unclaimed_key], 32)

# delegated_hashed_bins() only assigns the public key(s) of the hashed bins, so the private keys may
# be manually loaded as follows:
>>> for delegation in repository.targets('unclaimed')('django').delegations:
...   delegation.load_signing_key(private_unclaimed_key)

# Delegated roles can be restricted to particular paths with add_restricted_paths().
>>> repository.targets('unclaimed').add_restricted_paths('/path/to/repository/targets/django', 'django')
```

## Consistent Snapshots ##
The basic TUF repository we have generated above is adequate for repositories
that have some way of guaranteeing consistency of repository data.
A community software repository is one example where consistency of files and
metadata can become an issue.  Repositories of this kind are continually updated
by multiple maintainers and software authors uploading their packages, increasing
the likelihood that a client downloading version X of a release unexpectedly
requests the target files of a version Y just released.

To guarantee consistency of metadata and target files, a repository may optionally
support multiple versions of `snapshot.json` simultaneously, where a client with
version 1 of `snapshot.json` can download `target_file.zip` and another client with
version 2 of `snapshot.json` can also download a different `target_file.zip` (same file
name, but different file digest.)  If the `consistent_snapshot` parameter of write() is `True`,
metadata and target file names on the file system have their digests prepended (note: target file
names specified in metadata do not have digests included in their names.)

The repository maintainer is responsible for the duration of multiple versions
of metadata and target files available on a repository.  Generating consistent
metadata and target files on the repository is enabled by setting the
`consistent_snapshot` argument of write(): 
```Python
>>> repository.write(consistent_snapshot=True)
```
