# Repository Management #

## Table of Contents ##
- [How to Create and Modify a TUF Repository](#how-to-create-and-modify-a-tuf-repository)
  - [Overview](#overview)
  - [Keys](#keys)
    - [Create RSA Keys](#create-rsa-keys)
    - [Import RSA Keys](#import-rsa-keys)
    - [Create and Import Ed25519 Keys](#create-and-import-ed25519-keys)
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
- [How to Perform an Update](#how-to-perform-an-update)
- [Blocking Malicious Updates](#blocking-malicious-updates)
  - [Arbitrary Package Attack](#arbitrary-package-attack)
  - [Rollback Attack](#rollback-attack)
  - [Indefinite Freeze Attack](#indefinite-freeze-attack)
  - [Endless Data Attack](#endless-data-attack)
  - [Compromised Key Attack](#compromised-key-attack)
  - [Slow Retrieval Attack](#slow-retrieval-attack)
- [Conclusion](#conclusion)

## How to Create and Modify a TUF Repository ##

### Overview ###
A software update system must follow two steps to integrate The Update
Framework (TUF).  First, it must add the framework to the client side of the
update system.  The [tuf.client.updater](client/README.md) module assists in
integrating TUF on the client side.  Second, the software repository on the
server side must be modified to include a minimum of four top-level metadata
(root.json, targets.json, snapshot.json, and timestamp.json).  No additional
software is required to convert a software repository to a TUF one.  The
repository tool that generates the required TUF metadata for a software
repository is the focus of this document.  In addition, the update procedure of
a TUF integration is demonstrated, and some malicious updates are attempted to
show how TUF protects against these attacks.

The [repository tool](repository_tool.py) contains functions to generate all of
the files needed to populate and manage a TUF repository.  The tool may either
be imported into a Python module, or used with the Python interpreter in
interactive mode.  For instance, here is an example of loading a TUF repository
in interactive mode:

```Bash
$ python
Python 2.7.3 (default, Sep 26 2013, 20:08:41) 
[GCC 4.6.3] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from tuf.repository_tool import *
>>> repository = load_repository("path/to/repository")
```

A repository object that encapsulates the metadata files of the repository can
be created or loaded by the repository tool.  Repository maintainers can modify
the repository object to manipulate the metadata files stored on the
repository.  TUF clients use the metadata files to validate files requested and
downloaded.  In addition to the repository object, where the majority of
changes are made, the repository tool provides functions to generate and
persist cryptographic keys.  The framework utilizes cryptographic keys to sign
and verify metadata files.

To begin, cryptographic keys are generated with the repository tool.  However,
before metadata files can be validated by clients and target files fetched in a
secure manner, public keys must be pinned to particular metadata roles and
metadata signed by role's private keys.  After covering keys, the four required
top-level metadata are created next.  Examples are given demonstrating the
expected work flow, where the metadata roles are created in a specific order,
keys imported and loaded, and metadata signed and written to disk.  Lastly,
target files are added to the repository, and a custom delegation performed to
extend the default roles of the repository.  By the end, a fully populated TUF
repository is generated that can be used by clients to securely download
updates.

### Keys ###
The repository tool supports multiple public-key algorithms, such as
[RSA](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29) and
[Ed25519](http://ed25519.cr.yp.to/), and multiple cryptography libraries.
Which cryptography library to use is determined by the default, or user modified,
settings in [conf.py](conf.py).

The [PyCrypto](https://www.dlitz.net/software/pycrypto/) library may be
selected to generate RSA keys and
[RSA-PSS](https://en.wikipedia.org/wiki/RSA-PSS) signatures.  If generation of
Ed25519 signatures is needed, the [PyNaCl](https://github.com/pyca/pynacl)
library setting should be enabled.  PyNaCl is a Python binding to the
Networking and Cryptography Library.  For key storage, RSA keys may be stored
in PEM or JSON format, and Ed25519 keys in JSON format.  Private keys, for both
RSA and Ed25519, are encrypted and passphrase-protected (strengthened with
PBKDF2-HMAC-SHA256.)  Generating, importing, and loading cryptographic key
files can be done with functions available in the repository tool.

To start, a public and private RSA key pair is generated with the
`generate_and_write_rsa_keypair()` function.  The keys generated next are
needed to sign the repository metadata files created in upcoming sub-sections.

#### Create RSA Keys ####
```python
>>> from tuf.repository_tool import *

# Generate and write the first of two root keys for the TUF repository.  The
# following function creates an RSA key pair, where the private key is saved to
# "keystore/root_key" and the public key to "keystore/root_key.pub" (both saved
# to the current working directory).  The 'keystore' directory can be manually
# created in the current directory to store the keys created in these examples.
# If 'keystore' directory does not exist, it will be created. 
>>> generate_and_write_rsa_keypair("keystore/root_key", bits=2048, password="password")

# If the key length is unspecified, it defaults to 3072 bits. A length of less 
# than 2048 bits raises an exception. A password may be supplied as an 
# argument, otherwise a user prompt is presented.
>>> generate_and_write_rsa_keypair("keystore/root_key2")
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
# Continuing from the previous section . . .

# Import an existing public key.
>>> public_root_key = import_rsa_publickey_from_file("keystore/root_key.pub")

# Import an existing private key.  Importing a private key requires a password,
# whereas importing a public key does not.
>>> private_root_key = import_rsa_privatekey_from_file("keystore/root_key")
Enter a password for the encrypted RSA key:
```
`import_rsa_privatekey_from_file()` raises a `tuf.CryptoError` exception if the
key / password is invalid: tuf.CryptoError: RSA (public, private) tuple cannot
be generated from the encrypted PEM string: Bad decrypt. Incorrect password?
Note: The specific message provided by the exception might differ depending on
which cryptography library is used.

### Create and Import Ed25519 Keys ###
```Python
# Continuing from the previous section . . .

# Generate and write an Ed25519 key pair.  The private key is saved encrypted.
# A 'password' argument may be supplied, otherwise a prompt is presented.
>>> generate_and_write_ed25519_keypair('keystore/ed25519_key')
Enter a password for the Ed25519 key: 
Confirm:

# Import the ed25519 public key just created . . .
>>> public_ed25519_key = import_ed25519_publickey_from_file('keystore/ed25519_key.pub')

# and its corresponding private key.
>>> private_ed25519_key = import_ed25519_privatekey_from_file('keystore/ed25519_key')
Enter a password for the encrypted Ed25519 key: 
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

# Create a new Repository object that holds the file path to the repository and
# the four top-level role objects (Root, Targets, Snapshot, Timestamp).
# Metadata files are created when repository.write() is called.  The repository
# directory is created if it does not exist.  You may see log messages
# indicating any directories created.
>>> repository = create_new_repository("repository/")

# The Repository instance, 'repository', initially contains top-level Metadata
# objects.  Add one of the public keys, created in the previous section, to the
# root role.  Metadata is considered valid if it is signed by the public key's
# corresponding private key.
>>> repository.root.add_verification_key(public_root_key)

# Role keys (i.e., the key's keyid) may be queried.  Other attributes include:
# signing_keys, version, signatures, expiration, threshold, delegations
# (Targets role), and compressions.
>>> repository.root.keys
['b23514431a53676595922e955c2d547293da4a7917e3ca243a175e72bbf718df']

# Add a second public key to the root role.  Although previously generated and
# saved to a file, the second public key must be imported before it can added
# to a role.
>>> public_root_key2 = import_rsa_publickey_from_file("keystore/root_key2.pub")
>>> repository.root.add_verification_key(public_root_key2)

# Threshold of each role defaults to 1.   Maintainers may change the threshold
# value, but repository_tool.py validates thresholds and warns users.  Set the
# threshold of the root role to 2, which means the root metadata file is
# considered valid if it contains at least two valid signatures.  We also
# load the second private key, which hasn't been imported yet.
>>> repository.root.threshold = 2
>>> private_root_key2 = import_rsa_privatekey_from_file("keystore/root_key2", password="password")

# Load the root signing keys to the repository, which writeall() or write()
# (write multiple roles, or a single role, to disk) uses to sign the root
# metadata.  The load_signing_key() method SHOULD warn when the key is NOT
# explicitly allowed to sign for it.

>>> repository.root.load_signing_key(private_root_key)
>>> repository.root.load_signing_key(private_root_key2)

# Print the roles that are "dirty" (i.e., that have not been written to disk
# or have changed.
>>> repository.dirty_roles()
Dirty roles: ['root']

# The status() function also prints the next role(s) that needs editing.
# In this example, the 'targets' role needs editing next, since the root
# role is now fully valid.
>>> repository.status()
'targets' role contains 0 / 1 public keys.

# In the next section, update the other top-level roles and create a repository
# with valid metadata.
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
>>> generate_and_write_rsa_keypair("keystore/targets_key", password="password")
>>> generate_and_write_rsa_keypair("keystore/snapshot_key", password="password")
>>> generate_and_write_rsa_keypair("keystore/timestamp_key", password="password")

# Add the public keys of the remaining top-level roles.
>>> repository.targets.add_verification_key(import_rsa_publickey_from_file("keystore/targets_key.pub"))
>>> repository.snapshot.add_verification_key(import_rsa_publickey_from_file("keystore/snapshot_key.pub"))
>>> repository.timestamp.add_verification_key(import_rsa_publickey_from_file("keystore/timestamp_key.pub"))

# Import the signing keys of the remaining top-level roles.  Prompt for passwords.
>>> private_targets_key = import_rsa_privatekey_from_file("kestore/targets_key")
Enter a password for the encrypted RSA key:

>>> private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key")
Enter a password for the encrypted RSA key:

>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for the encrypted RSA key:

# Load the signing keys of the remaining roles so that valid signatures are
# generated when repository.writeall() is called.
>>> repository.targets.load_signing_key(private_targets_key)
>>> repository.snapshot.load_signing_key(private_snapshot_key)
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Write all metadata to "repository/metadata.staged/".  The common case is to crawl the
# filesystem for all delegated roles in "metadata.staged/".
>>> repository.writeall()
```

### Targets ###
TUF verifies target files by including their length, hash(es),
and filepath in metadata.  The filepaths are relative to a `targets/` directory
on the repository.  A TUF client can download a target file by first updating 
the latest copy of metadata (and thus available targets), verifying that their
length and hashes are valid, and then saving them locally to complete the update
process.

In this section, the target files intended for clients are added to a repository
and listed in `targets.json` metadata.

#### Add Target Files ####

The repository maintainer adds target files to roles (e.g., `targets`,
`unclaimed`) by specifying target paths.  Files at these target paths
must exist before the repository tool can generate and add their (hash(es),
length, filepath) to metadata.

The actual target files are added first to the `targets/` directory of the
repository.

```Bash
# Create and save target files to the targets directory of the repository.
$ cd repository/targets/
$ echo 'file1' > file1.txt
$ echo 'file2' > file2.txt
$ echo 'file3' > file3.txt
$ mkdir myproject; echo 'file4' > myproject/file4.txt
```

With the target files available on the `targets/` directory of the repository,
the `add_targets()` method of a Targets role can be called to add the target
files to metadata.

```python
>>> from tuf.repository_tool import *
>>> import os

# Load the repository created in the previous section.  This repository so far
# contains metadata for the top-level roles, but no target paths are yet listed
# in targets metadata.
>>> repository = load_repository("repository/")

# get_filepaths_in_directory() returns a list of file paths in a directory.  It can also return
# files in sub-directories if 'recursive_walk' is True.
>>> list_of_targets = repository.get_filepaths_in_directory("repository/targets/",
                                                        recursive_walk=False, followlinks=True) 

# Add the list of target paths to the metadata of the top-level Targets role.
# Any target file paths that might already exist are NOT replaced.
# add_targets() does not create or move target files on the file system.  Any
# target paths added to a role must be relative to the targets directory,
# otherwise an exception is raised.
>>> repository.targets.add_targets(list_of_targets)
```

The private keys of roles affected by the changes above must now be imported and
loaded.  `targets.json` must be signed because a target file was added to its
metadata.  `snapshot.json` keys must be loaded and its metadata signed because
`targets.json` has changed.  Similarly, since `snapshot.json` has changed, the
`timestamp.json` role must also be signed.

```Python
# The private key of the updated targets metadata must be loaded before it can
# be signed and written (Note the load_repository() call above).
>>> private_targets_key = import_rsa_privatekey_from_file("keystore/targets_key")
Enter a password for the encrypted RSA key:

>>> repository.targets.load_signing_key(private_targets_key)

# Due to the load_repository() and new versions of metadata, we must also load
# the private keys of Snapshot and Timestamp to generate a valid set of metadata.
>>> private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key")
Enter a password for the encrypted RSA key:
>>> repository.snapshot.load_signing_key(private_snapshot_key)

>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for the encrypted RSA key:
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Which roles are dirty?
>>> repository.dirty_roles()
Dirty roles: ['timestamp', 'snapshot', 'targets']

# Generate new versions of the modified top-level metadata (targets, snapshot,
# and timestamp).
>>> repository.writeall()
```

#### Remove Target Files ####

Target files previously added to roles may also be removed.  Removing a target
file requires first removing the target from a role and then writing the
new metadata to disk.
```python
# Continuing from the previous section . . .

# Remove a target file listed in the "targets" metadata.  The target file is
# not actually deleted from the file system.
>>> repository.targets.remove_target("/path/to/repository/targets/file3.txt")

# repository.write() creates any new metadata files, updates those that have
# changed, and any that need updating to make a new "snapshot" (new
# snapshot.json and timestamp.json).
>>> repository.write()
```

### Delegations ###
All of the target files available on the repository created so far have been
added to one role.  But, what if multiple developers are responsible for the
files of a project?  What if responsiblity separation is desired?  Performing a
delegation, where one parent role delegates trust of some paths to another
role, is an option for integrators that require custom roles in addition to the
top-level roles available by default.

In the next sub-section, a delegated `unclaimed` role is delegated from the
top-level `targets` role.  The `targets` role specifies the delegated role's
public keys, the paths it is trusted to provide, and its role name.
Futhermore, the example below demonstrates a nested delegation from `unclaimed`
to `django`.  Once a parent role has delegated trust, delegated roles may add
targets and generate signed metadata.


```python
# Continuing from the previous section . . .

# Generate a key for a new delegated role named "django".
>>> generate_and_write_rsa_keypair("keystore/django_key", bits=2048, password="password")
>>> public_django_key = import_rsa_publickey_from_file("keystore/django_key.pub")

# Make a delegation from "targets" to "django", initially containing zero
# targets.
# delegate(rolename, list_of_public_keys, list_of_file_paths, threshold,
#          restricted_paths, path_hash_prefixes)
>>> repository.targets.delegate("django", [public_django_key], [])

# Load the private key of "django" so that signatures are later added and
# valid metadata is created.
>>> private_django_key = import_rsa_privatekey_from_file("keystore/django_key")
Enter a password for the encrypted RSA key:

>>> repository.targets("django").load_signing_key(private_django_key)

# Update an attribute of the unclaimed role.
>>> repository.targets("django").version = 2

# Dirty roles?
$ repository.dirty_roles()
Dirty roles: ['timestamp', 'snapshot', 'targets', 'django']

#  Write the metadata of "django", "root", "targets", "snapshot,
# and "timestamp".
>>> repository.writeall()
```

#### Revoke Delegated Role ####
```python
# Continuing from the previous section . . .

# Create a delegated role that will be revoked in the next step.
>>> repository.targets('unclaimed').delegate("flask", [public_unclaimed_key], [])

# Revoke "flask" and write the metadata of all remaining roles.
>>> repository.targets('unclaimed').revoke("flask")
>>> repository.write()
```

#### Wrap-up ####

In summary, the five steps a repository maintainer follows to create a basic TUF
repository are:

1.  Generate a repository directory that contains TUF metadata and the target files.
2.  Create top-level roles (`root.json`, `snapshot.json`, `targets.json`, and `timestamp.json`.) 
3.  Add target files to the `targets` role.
4.  Optionally, create delegated roles to distribute target files.
5.  Write the changes.

The repository tool saves repository changes to a `metadata.staged` directory.
Repository maintainers may push final changes to the "live" repository by
copying the staged directory to its destination. 
```Bash
# Copy the staged metadata directory changes to the live repository.
$ cp -r "repository/metadata.staged/" "repository/metadata/"
```

## Consistent Snapshots ##
The basic TUF repository we have generated above is adequate for repositories
that have some way of guaranteeing consistency of repository data.
A community software repository is one example where consistency of files and
metadata can become an issue.  Repositories of this kind are continually updated
by multiple maintainers and software authors uploading their packages, increasing
the likelihood that a client downloading version X of a release unexpectedly
requests the target files of a version Y just released.

To guarantee consistency of metadata and target files, a repository may
optionally support multiple versions of `snapshot.json` simultaneously, where a
client with version 1 of `snapshot.json` can download `target_file.zip` and
another client with version 2 of `snapshot.json` can also download a different
`target_file.zip` (same file name, but different file digest.)  If the
`consistent_snapshot` parameter of write() is `True`, metadata and target file
names on the file system have their digests prepended (note: target file names
specified in metadata do not contain digests in their names.)

The repository maintainer is responsible for the duration of multiple versions
of metadata and target files available on a repository.  Generating consistent
metadata and target files on the repository is enabled by setting the
`consistent_snapshot` argument of write(): 
```Python
>>> repository.write(consistent_snapshot=True)
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
`delegate_hashed_bins()`.  The metadata files of delegated roles will be nearly
equal in size (i.e., target file paths are uniformly distributed by calculating
the target filepath's digest and determining which bin it should reside in.)
The updater client will use "lazy bin walk" (visit and download the minimum
metadata required to find a target) to find a target file's hashed bin
destination.  This method is intended for repositories with a large number of
target files, a way of easily distributing and managing the metadata that lists
the targets, and minimizing the number of metadata files (and size) downloaded
by the client.

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
>>> repository.targets('django').delegate_hashed_bins(targets, [public_unclaimed_key], 32)

# delegated_hashed_bins() only assigns the public key(s) of the hashed bins, so
# the private keys may be manually loaded as follows:
>>> for delegation in repository.targets('django').delegations:
...   delegation.load_signing_key(private_unclaimed_key)

# Delegated roles can be restricted to particular paths with add_restricted_paths().
>>> repository.targets('unclaimed').add_restricted_paths('/path/to/repository/targets/django/*', 'django')
```

## How to Perform an Update ##

Documentation for setting up a TUF client and performing an update is
provided [here](client_setup_and_repository_example.md).  The documentation
there is provided here for convenience.

The following [repository tool](README.md) function creates a directory
structure that a client downloading new software using TUF (via
tuf/client/updater.py) expects. The `root.json` metadata file must exist, and
also the directories that hold the metadata files downloaded from a repository.
Software updaters integrating with TUF may use this directory to store TUF
updates saved on the client side.

```python
>>> from tuf.repository_tool import *
>>> create_tuf_client_directory("repository/", "client/")
```

`create_tuf_client_directory()` moves metadata from `repository/metadata` to
`client/` in this example.  The repository in `repository/` may be the
repository example created in the repository tool [README](README.md).

## Test TUF Locally ##
Run the local TUF repository server.
```Bash
$ cd "repository/"; python -m SimpleHTTPServer 8001
```

Retrieve targets from the TUF repository and save them to `client/`.  The
`basic_client.py` script is available in the 'scripts' directory.  In the
following example, it is copied to the 'client' directory and executed from
there.  In a different command-line prompt . . .
```Bash
$ cd "client/"
$ ls
metadata/

# Copy tuf/scripts/basic_client.py to current directory.  Note: You should
# activate another "tufenv" virtualenv if using a new windows/tab, otherwise
# the local Python installation would be incorrectly used.
$ python basic_client.py --repo http://localhost:8001
$ ls . targets/
.:
metadata  targets  tuf.log

targets/:
file1.txt  file2.txt file3.txt
```

## Blocking Malicious Updates ##
TUF protects against a number of attacks, some of which include rollback,
arbitrary package, and mix and match attacks.  We begin this section on
blocking malicious updates by demonstrating how the client rejects a
target file downloaded from the repository that doesn't match what is
listed in metadata.

### Arbitrary Package Attack ###
In an arbitrary package attack, an  attacker installs anything they want on the
client system. That is, an attacker can provide arbitrary files in response to
download requests and the files will not be detected as illegitimate.  We
simulate an arbitrary package attack by creating a "malicious" target file
that our client attempts to fetch.

```Bash
$ mv 'repository/targets/file3.txt' 'repository/targets/file3.txt.backup'
$ echo 'bad_target' > 'repository/targets/file3.txt'
```

We next reset our local timestamp (so that a new update is prompted), and 
the target files previously downloaded by the client.
```Bash
rm -rf "client/targets/" "client/metadata/current/timestamp.json"
```

The client now performs an update and should detect the invalid target file...
```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  localhost:8001: BadHashError()
```

The log file (tuf.log) saved to the current working directory contains more
information on the update procedure and the cause of the BadHashError.
```Bash
...

BadHashError: Observed
hash ('f569179171c86aa9ed5e8b1d6c94dfd516123189568d239ed57d818946aaabe7') !=
expected hash (u'94f6e58bd04a4513b8301e75f40527cf7610c66d1960b26f6ac2e743e108bdac')

[2016-09-30 15:06:44,704 UTC] [tuf.client.updater] [ERROR] [_get_file:1394@updater.py]

Failed to update /file3.txt from all mirrors: {u'http://localhost:8001/targets/file3.txt': BadHashError()}
```


### Indefinite Freeze Attack ###
In an indefinite freeze attack, an attacker continues to present a software
update system with the same files the client has already seen. The result is
that the client does not know that new files are available.   Although the
client would be unable to prevent an attacker or compromised repository from
feeding it stale metadata, it can at least detect when an attacker is doing so
indefinitely.  The signed metadata used by TUF contains an "expires" field that
indicates when the expired metadata should no longer be trusted.

In the following simulation, the client first tries to perform an update.

```Bash
$ python basic_client.py --repo http://localhost:8001 
```

According to the logger (`tuf.log` file in the current working directory),
everything appears to be up-to-date.  The remote server should also show that
the client retrieved only the timestamp.json file.  Let's suppose now that an
attacker continues to feed our client the same stale metadata.  If we were to
move the time to a future date that would cause metadata to expire, the TUF
framework should raise an exception or error to indicate that the metadata
should no longer be trusted.

```Bash
$ sudo date -s '2080-12-25 12:34:56'
Wed Dec 25 12:34:56 EST 2080

$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': ExpiredMetadataError(u"Metadata u'root' expired on Tue Jan  1 00:00:00 2030 (UTC).",)
```

Note: Reset the date to continue with the rest of the attacks.


### Rollback Attack ###
In a rollback attack, an attacker presents a software update system with older
files than those the client has already seen, causing the client to use files
older than those the client knows about.  We begin this attack example by
saving the current version of the Timestamp file available on the repository.
This saved file will later be served to the client to see if it is rejected.
The client should not accept versions of metadata that is older than 
previously trusted.

Navigate to the directory containing the server's files and save the current
timestamp.json to a temporary location:
```Bash
$ cp repository/metadata/timestamp.json /tmp
```

We should now generate a new Timestamp file on the repository side.
```Bash
$ python
>>> from tuf.repository_tool import * 
>>> repository = load_repository('repository')
>>> repository.timestamp.version
1
>>> repository.timestamp.version = 2
>>> repository.dirty_roles()
Dirty roles: [u'timestamp']
>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for the encrypted RSA file: 
>>> repository.timestamp.load_signing_key(private_timestamp_key)
>>> repository.write('timestamp')

$ cp repository/metadata.staged/* repository/metadata
```

Now start the HTTP server from the server's directory containing the
'repository' subdirectory.
```Bash
$ python -m SimpleHTTPServer 8001
```

And perform an update so that the client retrieves the updated timestamp.json.
```Bash
$ python basic_client.py --repo http://localhost:8001
```

Finally, move the previous timestamp.json file to the current live repository
and have the client try to download the outdated version.  The client should
reject it!
```Bash
$ cp /tmp/timestamp.json repository/metadata/
$ python -m SimpleHTTPServer 8001
```

On the client side, perform an update...
```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': ReplayedMetadataError()
```

The tuf.log file contains more information about the Rollback error.  Please
reset the timestamp.json to the latest version, which can be found in the
'repository/metadata.staged' subdirectory.

```Bash
$ cp repository/metadata.staged/timestamp.json repository/metadata
```


### Endless Data Attack ###
In an endless data attack, an attacker responds to a file download request with
an endless stream of data, causing harm to clients (e.g., a disk partition
filling up or memory exhaustion).  In this simulated attack, we append
extra data to one of the target files available on the repository.
The client should only download the exact number of bytes it expects for
a requested target file (according to what is listed in trusted metadata).

```Bash
$ python -c "print 'a' * 1000" >> repository/targets/file1.txt
```

Now delete the local metadata and target files on the client side so
that remote metadata and target files are downloaded again.
```Bash
$ rm -rf repository/targets/
$ rm repository/metadata/current/snapshot.json* repository/metadata/current/timestamp.json*
```

Lastly, perform an update to verify that the file1.txt is downloaded up to the
expected size, and no more.  The target file available on the repository
does contain more data than expected, though.

```Bash
$ python basic_client.py --repo http://localhost:8001 
```

At this point, part of the "file1.txt" file should have been fetched.  That is,
up to 31 bytes of it should have been downloaded, and the rest of the maliciously
appended data ignored.  If we inspect the logger, we'd disover the following:

```Bash
[2016-10-06 21:37:39,092 UTC] [tuf.download] [INFO] [_download_file:235@download.py]
Downloading: u'http://localhost:8001/targets/file1.txt'                         
                                                                                 
[2016-10-06 21:37:39,145 UTC] [tuf.download] [INFO] [_check_downloaded_length:610@download.py]
Downloaded 31 bytes out of the expected 31 bytes.                               
                                                                                 
[2016-10-06 21:37:39,145 UTC] [tuf.client.updater] [INFO] [_get_file:1372@updater.py]
Not decompressing http://localhost:8001/targets/file1.txt                       
                                                                                 
[2016-10-06 21:37:39,145 UTC] [tuf.client.updater] [INFO] [_check_hashes:778@updater.py]
The file's sha256 hash is correct: 65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da
```

Indeed, the sha256 sum of the first 31 bytes of the "file1.txt" available
on the repository should match to what is trusted.  The client did not
downloaded the appended data.


### Compromised Key Attack ###
An attacker who is able to compromise a single key or less than a given
threshold of keys can compromise clients. This includes relying on a single
online key (such as only being protected by SSL) or a single offline key (such
as most software update systems use to sign files).  In this example, we
attempt to sign a role file with less-than-a-threshold number of keys.  The
single key (suppose this is a compromised key) used for signing is to
demonstrate that roles must be signed with the total number of keys required
for the role.  In order to compromise a role, an attacker would have to
compromise the full set of keys.  This approach of requiring a threshold number
of signatures provides compromise resilience.

Let's attempt to sign a new snapshot file with a less-than-threshold number of
keys.  The client should reject the partially signed snapshot file served by
the repository (or imagine that it is a compromised repository).

```Bash
$ python
>>> from tuf.repository_tool import *
>>> repository = load_repository('repository')
>>> repository.root.version = 8
>>> private_root_key = import_rsa_privatekey_from_file("keystore/root_key", password="password")
>>> repository.root.load_signing_key(private_root_key)
>>> private_root_key2 = import_rsa_privatekey_from_file("keystore/root_key2", password="password")
>>> repository.root.load_signing_key(private_root_key2)

>>> repository.snapshot.version = 8
>>> repository.snapshot.threshold = 2
>>> private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key", password="password")
>>> repository.snapshot.load_signing_key(private_snapshot_key)

>>> repository.timestamp.version = 8
>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key", password="password")
>>> repository.timestamp.load_signing_key(private_timestamp_key)

>>> repository.write('root')
>>> repository.write('snapshot')
>>> repository.write('timestamp')

$ cp repository/metadata.staged/* repository/metadata
```

The client should not attempt to refresh the top-level metadata and the
partially written snapshot.json.

```Bash
$ python basic_client.py --repo http://localhost:8001
Error: No working mirror was found:
  u'localhost:8001': BadSignatureError()
```


### Slow Retrieval Attack ###
In a slow retrieval attack, an attacker responds to clients with a very slow
stream of data that essentially results in the client never continuing the
update process.  For this example, we simulate a slow retrieval attack by
spawning a server that serves our update client data at a slow rate.  TUF
should not be vulnerable to this attack, and the framework should raise an
exception or error when it detects that a malicious server is serving it data
at a slow enough rate.

We first spawn a server that slowly streams data to a client request.  The
'slow_retrieval_server.py' module can be copied over to the '../demo_repository'
directory from which to launch it.

```Bash
$ python slow_retrieval_server.py 8002 mode_2
```

The client may now make a request to the slow server on port 8002.  However,
before doing so, we'll need to reduce (for the purposes of this demo) the
minimum average download rate allowed.  Open the '.../demo/tuf/tuf/conf.py'
file and set MIN_AVERAGE_DOWNLOAD_SPEED to 1.  This should make it so
that client correctly detects the slow retrieval server's delayed streaming.

```Bash
$ python basic_client.py --verbose 1 --repo http://localhost:8002
Error: No working mirror was found:
  u'localhost:8002': SlowRetrievalError()
```

The framework should detect the attack and raise a SlowRetrievalError
exception to the client application.


## Conclusion ##
These are just some of the attacks that TUF provides protection against.  For
more attacks and updater weaknesses, please see the
[Security](https://github.com/theupdateframework/tuf/blob/develop/SECURITY.md)
page.
