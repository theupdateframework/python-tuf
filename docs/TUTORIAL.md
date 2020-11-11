# Advanced Tutorial #

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

## How to Create and Modify a TUF Repository ##

### Overview ###
A software update system must follow two steps to integrate The Update
Framework (TUF).  First, it must add the framework to the client side of the
update system.  The [tuf.client.updater](../tuf/client/README.md) module assists in
integrating TUF on the client side.  Second, the software repository on the
server side must be modified to include a minimum of four top-level metadata
(root.json, targets.json, snapshot.json, and timestamp.json).  No additional
software is required to convert a software repository to a TUF one.  The
low-level repository tool that generates the required TUF metadata for a
software repository is the focus of this tutorial.  There is also separate
document that [demonstrates how TUF protects against malicious
updates](../tuf/ATTACKS.md).

The [repository tool](../tuf/repository_tool.py) contains functions to generate
all of the files needed to populate and manage a TUF repository.  The tool may
either be imported into a Python module, or used with the Python interpreter in
interactive mode.

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
[Ed25519](https://ed25519.cr.yp.to/), and multiple cryptography libraries.

Using [RSA-PSS](https://tools.ietf.org/html/rfc8017#section-8.1) or
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
signatures requires the [cryptography](https://cryptography.io/) library. If
generation of Ed25519 signatures is needed
[PyNaCl](https://github.com/pyca/pynacl) library should be installed. This
tutorial assumes both dependencies are installed: refer to
[Installation Instructions](INSTALLATION.rst#install-with-more-cryptographic-flexibility)
for details.

The Ed25519 and ECDSA keys are stored in JSON format and RSA keys are stored in PEM
format. Private keys are encrypted and passphrase-protected (strengthened with
PBKDF2-HMAC-SHA256.)  Generating, importing, and loading cryptographic key
files can be done with functions available in the repository tool.

To start, a public and private RSA key pair is generated with the
`generate_and_write_rsa_keypair()` function.  The keys generated next are
needed to sign the repository metadata files created in upcoming sub-sections.

Note:  In the instructions below, lines that start with `>>>` denote commands
that should be entered by the reader, `#` begins the start of a comment, and
text without prepended symbols is the output of a command.

#### Create RSA Keys ####
```python
>>> from tuf.repository_tool import *

# Generate and write the first of two root keys for the TUF repository.  The
# following function creates an RSA key pair, where the private key is saved to
# "root_key" and the public key to "root_key.pub" (both saved to the current
# working directory).
>>> generate_and_write_rsa_keypair(password="password", filepath="root_key", bits=2048)

# If the key length is unspecified, it defaults to 3072 bits. A length of less
# than 2048 bits raises an exception. A similar function is available to supply
# a password on the prompt. If an empty password is entered, the private key
# is saved unencrypted.
>>> generate_and_write_rsa_keypair_with_prompt(filepath="root_key2")
enter password to encrypt private key file '/path/to/root_key2'
(leave empty if key should not be encrypted):
Confirm:
```
The following four key files should now exist:

1.  **root_key**
2.  **root_key.pub**
3.  **root_key2**
4.  **root_key2.pub**

If a filepath is not given, the KEYID of the generated key is used as the
filename.  The key files are written to the current working directory.
```python
# Continuing from the previous section . . .
>>> generate_and_write_rsa_keypair_with_prompt()
enter password to encrypt private key file '/path/to/KEYID'
(leave empty if key should not be encrypted):
Confirm:
```

### Import RSA Keys ###
```python
# Continuing from the previous section . . .

# Import an existing public key.
>>> public_root_key = import_rsa_publickey_from_file("root_key.pub")

# Import an existing private key.  Importing a private key requires a password,
# whereas importing a public key does not.
>>> private_root_key = import_rsa_privatekey_from_file("root_key")
enter password to decrypt private key file '/path/to/root_key'
(leave empty if key not encrypted):
```

### Create and Import Ed25519 Keys ###
```Python
# Continuing from the previous section . . .

# The same generation and import functions as for rsa keys exist for ed25519
>>> generate_and_write_ed25519_keypair_with_prompt(filepath='ed25519_key')
enter password to encrypt private key file '/path/to/ed25519_key'
(leave empty if key should not be encrypted):
Confirm:

# Import the ed25519 public key just created . . .
>>> public_ed25519_key = import_ed25519_publickey_from_file('ed25519_key.pub')

# and its corresponding private key.
>>> private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key')
enter password to decrypt private key file '/path/to/ed25519_key'
(leave empty if key should not be encrypted):
```

Note: Methods are also available to generate and write keys from memory.
* generate_ed25519_key()
* generate_ecdsa_key()
* generate_rsa_key()

* import_ecdsakey_from_pem(pem)
* import_rsakey_from_pem(pem)

### Create Top-level Metadata ###
The [metadata document](METADATA.md) outlines the JSON files that must exist
on a TUF repository.  The following sub-sections demonstrate the
`repository_tool.py` calls repository maintainers may issue to generate the
required roles.  The top-level roles to be created are `root`, `timestamp`,
`snapshot`, and `target`.

We begin with `root`, the locus of trust that specifies the public keys of the
top-level roles, including itself.


#### Create Root ####
```python
# Continuing from the previous section . . .

# Create a new Repository object that holds the file path to the TUF repository
# and the four top-level role objects (Root, Targets, Snapshot, Timestamp).
# Metadata files are created when repository.writeall() or repository.write()
# are called.  The repository directory is created if it does not exist.  You
# may see log messages indicating any directories created.
>>> repository = create_new_repository("repository")

# The Repository instance, 'repository', initially contains top-level Metadata
# objects.  Add one of the public keys, created in the previous section, to the
# root role.  Metadata is considered valid if it is signed by the public key's
# corresponding private key.
>>> repository.root.add_verification_key(public_root_key)

# A role's verification key(s) (to be more precise, the verification key's
# keyid) may be queried.  Other attributes include: signing_keys, version,
# signatures, expiration, threshold, and delegations (attribute available only
# to a Targets role).
>>> repository.root.keys
['b23514431a53676595922e955c2d547293da4a7917e3ca243a175e72bbf718df']

# Add a second public key to the root role.  Although previously generated and
# saved to a file, the second public key must be imported before it can added
# to a role.
>>> public_root_key2 = import_rsa_publickey_from_file("root_key2.pub")
>>> repository.root.add_verification_key(public_root_key2)

# The threshold of each role defaults to 1.   Maintainers may change the
# threshold value, but repository_tool.py validates thresholds and warns users.
# Set the threshold of the root role to 2, which means the root metadata file
# is considered valid if it's signed by at least two valid keys.  We also load
# the second private key, which hasn't been imported yet.
>>> repository.root.threshold = 2
>>> private_root_key2 = import_rsa_privatekey_from_file("root_key2", password="password")

# Load the root signing keys to the repository, which writeall() or write()
# (write multiple roles, or a single role, to disk) use to sign the root
# metadata.
>>> repository.root.load_signing_key(private_root_key)
>>> repository.root.load_signing_key(private_root_key2)

# repository.status() shows missing verification and signing keys for the
# top-level roles, and whether signatures can be created (also see #955).
# This output shows that so far only the "root" role meets the key threshold and
# can successfully sign its metadata.
>>> repository.status()
'targets' role contains 0 / 1 public keys.
'snapshot' role contains 0 / 1 public keys.
'timestamp' role contains 0 / 1 public keys.
'root' role contains 2 / 2 signatures.
'targets' role contains 0 / 1 signatures.

# In the next section we update the other top-level roles and create a repository
# with valid metadata.
```

#### Create Timestamp, Snapshot, Targets
Now that `root.json` has been set, the other top-level roles may be created.
The signing keys added to these roles must correspond to the public keys
specified by the Root role.

On the client side, `root.json` must always exist.  The other top-level roles,
created next, are requested by repository clients in (Root -> Timestamp ->
Snapshot -> Targets) order to ensure required metadata is downloaded in a
secure manner.

```python
# Continuing from the previous section . . .

# 'datetime' module needed to optionally set a role's expiration.
>>> import datetime

# Generate keys for the remaining top-level roles.  The root keys have been set above.
>>> generate_and_write_rsa_keypair(password='password', filepath='targets_key')
>>> generate_and_write_rsa_keypair(password='password', filepath='snapshot_key')
>>> generate_and_write_rsa_keypair(password='password', filepath='timestamp_key')

# Add the verification keys of the remaining top-level roles.

>>> repository.targets.add_verification_key(import_rsa_publickey_from_file('targets_key.pub'))
>>> repository.snapshot.add_verification_key(import_rsa_publickey_from_file('snapshot_key.pub'))
>>> repository.timestamp.add_verification_key(import_rsa_publickey_from_file('timestamp_key.pub'))

# Import the signing keys of the remaining top-level roles.
>>> private_targets_key = import_rsa_privatekey_from_file('targets_key', password='password')
>>> private_snapshot_key = import_rsa_privatekey_from_file('snapshot_key', password='password')
>>> private_timestamp_key = import_rsa_privatekey_from_file('timestamp_key', password='password')

# Load the signing keys of the remaining roles so that valid signatures are
# generated when repository.writeall() is called.
>>> repository.targets.load_signing_key(private_targets_key)
>>> repository.snapshot.load_signing_key(private_snapshot_key)
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Optionally set the expiration date of the timestamp role.  By default, roles
# are set to expire as follows:  root(1 year), targets(3 months), snapshot(1
# week), timestamp(1 day).
>>> repository.timestamp.expiration = datetime.datetime(2080, 10, 28, 12, 8)

# Mark roles for metadata update (see #964, #958)
>>> repository.mark_dirty(['root', 'snapshot', 'targets', 'timestamp'])

# Write all metadata to "repository/metadata.staged/"
>>> repository.writeall()
```

### Targets ###
TUF makes it possible for clients to validate downloaded target files by
including a target file's length, hash(es), and filepath in metadata.  The
filepaths are relative to a `targets/` directory on the software repository.  A
TUF client can download a target file by first updating the latest copy of
metadata (and thus available targets), verifying that their length and hashes
are valid, and saving the target file(s) locally to complete the update
process.

In this section, the target files intended for clients are added to a
repository and listed in `targets.json` metadata.

#### Add Target Files ####

The repository maintainer adds target files to roles (e.g., `targets` and
`unclaimed`) by specifying their filepaths.  The target files must exist at the
specified filepaths before the repository tool can generate and add their
(hash(es), length, and filepath) to metadata.

First, the actual target files are manually created and saved to the `targets/`
directory of the repository:

```Bash
# Create and save target files to the targets directory of the software
# repository.
$ cd repository/targets/
$ echo 'file1' > file1.txt
$ echo 'file2' > file2.txt
$ echo 'file3' > file3.txt
$ mkdir myproject; echo 'file4' > myproject/file4.txt
$ cd ../../
```

With the target files available on the `targets/` directory of the software
repository, the `add_targets()` method of a Targets role can be called to add
the target filepaths to metadata.

```python
# Continuing from the previous section . . .

# NOTE: If you exited the Python interactive interpreter above you need to
# re-import the repository_tool-functions and re-load the repository and
# signing keys.
>>> from tuf.repository_tool import *

# The 'os' module is needed to gather file attributes, which will be included
# in a custom field for some of the target files added to metadata.
>>> import os

# Load the repository created in the previous section.  This repository so far
# contains metadata for the top-level roles, but no target paths are yet listed
# in targets metadata.
>>> repository = load_repository('repository')

# Create a list of all targets in the directory.
>>> list_of_targets = ['file1.txt', 'file2.txt', 'file3.txt']

# Add the list of target paths to the metadata of the top-level Targets role.
# Any target file paths that might already exist are NOT replaced, and
# add_targets() does not create or move target files on the file system.  Any
# target paths added to a role must fall under the expected targets directory,
# otherwise an exception is raised. The targets added to a role should actually
# exist once writeall() or write() is called, so that the hash and size of
# these targets can be included in Targets metadata.
>>> repository.targets.add_targets(list_of_targets)

# Individual target files may also be added to roles, including custom data
# about the target.  In the example below, file permissions of the target
# (octal number specifying file access for owner, group, others e.g., 0755) is
# added alongside the default fileinfo.  All target objects in metadata include
# the target's filepath, hash, and length.
# Note: target path passed to add_target() method has to be relative
# to the targets directory or an exception is raised.
>>> target4_filepath = 'myproject/file4.txt'
>>> target4_abspath = os.path.abspath(os.path.join('repository', 'targets', target4_filepath))
>>> octal_file_permissions = oct(os.stat(target4_abspath).st_mode)[4:]
>>> custom_file_permissions = {'file_permissions': octal_file_permissions}
>>> repository.targets.add_target(target4_filepath, custom_file_permissions)
```

The private keys of roles affected by the changes above must now be imported and
loaded.  `targets.json` must be signed because a target file was added to its
metadata.  `snapshot.json` keys must be loaded and its metadata signed because
`targets.json` has changed.  Similarly, since `snapshot.json` has changed, the
`timestamp.json` role must also be signed.

```Python
# Continuing from the previous section . . .

# The private key of the updated targets metadata must be re-loaded before it
# can be signed and written (Note the load_repository() call above).
>>> private_targets_key = import_rsa_privatekey_from_file('targets_key')
enter password to decrypt private key file '/path/to/targets_key'
(leave empty if key not encrypted):

>>> repository.targets.load_signing_key(private_targets_key)

# Due to the load_repository() and new versions of metadata, we must also load
# the private keys of Snapshot and Timestamp to generate a valid set of metadata.
>>> private_snapshot_key = import_rsa_privatekey_from_file('snapshot_key')
enter password to decrypt private key file '/path/to/snapshot_key'
(leave empty if key not encrypted):
>>> repository.snapshot.load_signing_key(private_snapshot_key)

>>> private_timestamp_key = import_rsa_privatekey_from_file('timestamp_key')
enter password to decrypt private key file '/path/to/timestamp_key'
(leave empty if key not encrypted):
>>> repository.timestamp.load_signing_key(private_timestamp_key)

# Mark roles for metadata update (see #964, #958)
>>> repository.mark_dirty(['snapshot', 'targets', 'timestamp'])

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
>>> repository.targets.remove_target('myproject/file4.txt')

# Mark roles for metadata update (see #964, #958)
>>> repository.mark_dirty(['snapshot', 'targets', 'timestamp'])

>>> repository.writeall()
```

#### Excursion: Dump Metadata and Append Signature ####

The following two functions are intended for those that wish to independently
sign metadata.  Repository maintainers can dump the portion of metadata that is
normally signed, sign it with an external signing tool, and append the
signature to already existing metadata.

First, the signable portion of metadata can be generated as follows:

```Python
>>> signable_content = dump_signable_metadata('repository/metadata.staged/timestamp.json')
```

Then, use a tool like securesystemslib to create a signature over the signable
portion. *Note, to make the signing key count towards the role's signature
threshold, it needs to be added to `root.json`, e.g. via
`repository.timestamp.add_verification_key(key)` (not shown in below snippet).*
```python
>>> from securesystemslib.formats import encode_canonical
>>> from securesystemslib.keys import create_signature
>>> private_ed25519_key = import_ed25519_privatekey_from_file('ed25519_key')
enter password to decrypt private key file '/path/to/ed25519_key'
>>> signature = create_signature(
...     private_ed25519_key, encode_canonical(signable_content).encode())
```

Finally, append the signature to the metadata
```Python
>>> append_signature(signature, 'repository/metadata.staged/timestamp.json')
```

Note that the format of the signature is the format expected in metadata, which
is a dictionary that contains a KEYID, the signature itself, etc.  See the
specification and [METADATA.md](METADATA.md) for a detailed example.

### Delegations ###
All of the target files available on the software repository created so far
have been added to one role (the top-level Targets role).  However, what if
multiple developers are responsible for the files of a project?  What if
responsibility separation is desired?  Performing a delegation, where one role
delegates trust of some paths to another role, is an option for integrators
that require additional roles on top of the top-level roles available by
default.

In the next sub-section, the `unclaimed` role is delegated from the top-level
`targets` role.  The `targets` role specifies the delegated role's public keys,
the paths it is trusted to provide, and its role name. <!--
TODO: Uncomment together with "Revoke Delegated Role" section below

Furthermore, the example
below demonstrates a nested delegation from `unclaimed` to `django`. Once a
role has delegated trust to another, the delegated role may independently add
targets and generate signed metadata.
-->

```python
# Continuing from the previous section . . .

# Generate a key for a new delegated role named "unclaimed".
>>> generate_and_write_rsa_keypair(password='password', filepath='unclaimed_key', bits=2048)
>>> public_unclaimed_key = import_rsa_publickey_from_file('unclaimed_key.pub')

# Make a delegation (delegate trust of 'myproject/*.txt' files) from "targets"
# to "unclaimed", where "unclaimed" initially contains zero targets.
>>> repository.targets.delegate('unclaimed', [public_unclaimed_key], ['myproject/*.txt'])

# Thereafter, we can access the delegated role by its name to e.g. add target
# files, just like we did with the top-level targets role.
>>> repository.targets("unclaimed").add_target("myproject/file4.txt")

# Load the private key of "unclaimed" so that unclaimed's metadata can be
# signed, and valid metadata created.
>>> private_unclaimed_key = import_rsa_privatekey_from_file('unclaimed_key', password='password')

>>> repository.targets("unclaimed").load_signing_key(private_unclaimed_key)

# Mark roles for metadata update (see #964, #958)
>>> repository.mark_dirty(['snapshot', 'targets','timestamp', 'unclaimed'])

>>> repository.writeall()
```

<!--
TODO: Integrate section with an updated delegation tutorial.
As it is now, it just messes up the state of the repository, i.e. marks
"unclaimed" as dirty, although there is nothing new to write.

#### Revoke Delegated Role ####
```python
# Continuing from the previous section . . .

# Create a delegated role that will be revoked in the next step...
>>> repository.targets('unclaimed').delegate("django", [public_unclaimed_key], ['bar*.tgz'])

# Revoke "django" and write the metadata of all remaining roles.
>>> repository.targets('unclaimed').revoke("django")
>>> repository.writeall()
```
-->


#### Wrap-up ####

In summary, the five steps a repository maintainer follows to create a TUF
repository are:

1.  Create a directory for the software repository that holds the TUF metadata and the target files.
2.  Create top-level roles (`root.json`, `snapshot.json`, `targets.json`, and `timestamp.json`.)
3.  Add target files to the `targets` role.
4.  Optionally, create delegated roles to distribute target files.
5.  Write the changes.

The repository tool saves repository changes to a `metadata.staged` directory.
Repository maintainers may push finalized changes to the "live" repository by
copying the staged directory to its destination.
```Bash
# Copy the staged metadata directory changes to the live repository.
$ cp -r "repository/metadata.staged/" "repository/metadata/"
```

## Consistent Snapshots ##
The basic TUF repository we have generated above is adequate for repositories
that have some way of guaranteeing consistency of repository data.  A community
software repository is one example where consistency of files and metadata can
become an issue.  Repositories of this kind are continually updated by multiple
maintainers and software authors uploading their packages, increasing the
likelihood that a client downloading version X of a release unexpectedly
requests the target files of a version Y just released.

To guarantee consistency of metadata and target files, a repository may
optionally support multiple versions of `snapshot.json` simultaneously, where a
client with version 1 of `snapshot.json` can download `target_file.zip` and
another client with version 2 of `snapshot.json` can also download a different
`target_file.zip` (same file name, but different file digest.)  If the
`consistent_snapshot` parameter of writeall() or write() are `True`, metadata
and target file names on the file system have their digests prepended (note:
target file names specified in metadata do not contain digests in their names.)

The repository maintainer is responsible for the duration of multiple versions
of metadata and target files available on a repository.  Generating consistent
metadata and target files on the repository is enabled by setting the
`consistent_snapshot` argument of `writeall()` or `write()` . Note that
changing the consistent_snapshot setting involves writing a new version of
root.

<!--
TODO: Integrate section with an updated consistent snapshot tutorial.
As it is now, it just messes up the state of the repository, i.e. marks
"root" as dirty, although all other metadata needs to be re-written with
<VERSION> prefix and target files need to be re-written with <HASH> prefix in
their filenames.

```Python
    # ----- Tutorial Section: Consistent Snapshots
>>> repository.root.load_signing_key(private_root_key)
>>> repository.root.load_signing_key(private_root_key2)
>>> repository.writeall(consistent_snapshot=True)
```
-->

## Delegate to Hashed Bins ##
Why use hashed bin delegations?

For software update systems with a large number of target files, delegating to
hashed bins (a special type of delegated role) might be an easier alternative
to manually performing the delegations.  How many target files should each
delegated role contain?  How will these delegations affect the number of
metadata that clients must additionally download in a typical update?  Hashed
bin delegations are available to integrators that rather not deal with the
management of delegated roles and a great number of target files.

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

We next provide a complete example of retrieving target paths to add to hashed
bins, performing the hashed bin delegations, signing them, and delegating paths
to some role.

```Python
# Continuing from the previous section . . .

# Remove 'myproject/file4.txt' from unclaimed role and instead further delegate
# all targets in myproject/ to hashed bins.
>>> repository.targets('unclaimed').remove_target("myproject/file4.txt")

# Get a list of target paths for the hashed bins.
>>> targets = ['myproject/file4.txt']

# Delegate trust to 32 hashed bin roles. Each role is responsible for the set
# of target files, determined by the path hash prefix. TUF evenly distributes
# hexadecimal ranges over the chosen number of bins (see output).
# To initialize the bins we use one key, which TUF warns us about (see output).
# However, we can assign separate keys to each bin, with the method used in
# previous sections, accessing a bin by its hash prefix range name, e.g.:
# "repository.targets('00-07').add_verification_key('public_00-07_key')".
>>> repository.targets('unclaimed').delegate_hashed_bins(
...     targets, [public_unclaimed_key], 32)
Creating hashed bin delegations.
1 total targets.
32 hashed bins.
256 total hash prefixes.
Each bin ranges over 8 hash prefixes.
Adding a verification key that has already been used. [repeated 32x]

# The hashed bin roles can also be accessed by iterating the "delegations"
# property of the delegating role, which we do here to load the signing key.
>>> for delegation in repository.targets('unclaimed').delegations:
...   delegation.load_signing_key(private_unclaimed_key)

# Mark roles for metadata update (see #964, #958)
>>> repository.mark_dirty(['00-07', '08-0f', '10-17', '18-1f', '20-27', '28-2f',
...   '30-37', '38-3f', '40-47', '48-4f', '50-57', '58-5f', '60-67', '68-6f',
...   '70-77', '78-7f', '80-87', '88-8f', '90-97', '98-9f', 'a0-a7', 'a8-af',
...   'b0-b7', 'b8-bf', 'c0-c7', 'c8-cf', 'd0-d7', 'd8-df', 'e0-e7', 'e8-ef',
...   'f0-f7', 'f8-ff', 'snapshot', 'timestamp', 'unclaimed'])

>>> repository.writeall()

```

## How to Perform an Update ##

The following [repository tool](../tuf/repository_tool.py) function creates a directory
structure that a client downloading new software using TUF (via
[tuf/client/updater.py](../tuf/client/updater.py)) expects. The `root.json` metadata file must exist, and
also the directories that hold the metadata files downloaded from a repository.
Software updaters integrating TUF may use this directory to store TUF updates
saved on the client side.

```python
>>> from tuf.repository_tool import *
>>> create_tuf_client_directory("repository/", "client/tufrepo/")
```

`create_tuf_client_directory()` moves metadata from `repository/metadata` to
`client/` in this example.  The repository in `repository/` may be the
repository example created earlier in this document.

## Test TUF Locally ##
Run the local TUF repository server.
```Bash
$ cd "repository/"; python -m SimpleHTTPServer 8001
```

If running Python 3:
```Bash
$ cd "repository/"; python3 -m http.server 8001
```

We next retrieve targets from the TUF repository and save them to `client/`.
The `client.py` script is available to download metadata and files from a
specified repository.  In a different command-line prompt, where `tuf` is
installed . . .
```Bash
$ cd "client/"
$ ls
tufrepo/

$ client.py --repo http://localhost:8001 file1.txt
$ ls . tuftargets/
.:
tufrepo  tuftargets

tuftargets/:
file1.txt
```
