## Create TUF Repository

### Keys

#### Create RSA Keys
```python
from libtuf import *


# Generate and write the first of two root keys for the repository.
# The following function creates an RSA key pair, where the private key is saved to
# “path/to/root_key” and the public key to “path/to/root_key.pub”.
generate_and_write_rsa_keypair("path/to/root_key",bits=2048,password="password")

#if thhe key length is unspecified, it defaults to 3072 bits. A length of then 
#than 2048 bits prints an error mesage. A password may be supplied as an 
#argument, otherwise a user prompt is presented
generate_and_write_rsa_keypair("path/to/root_key2")
Enter a password for the RSA key:
Confirm:
```
The following four files should now exist:

1. root_key
2. root_key.pub
3. root_key2
4. root_key2.pub

### Import RSA Keys
```python
from libtuf import *

#import an existing public key
public_root_key = import_rsa_publickey_from_file("path/to/root_key.pub")

#import an existing private key
private_root_key = import_rsa_privatekey_from_file("path/to/root_key)
Enter a password for the RSA key:
Confirm:
```
At the time of importing the private RSA, a tuf.CryptoError can be thrown if
the key is invalid

### Create a new Repository

#### Create Root
```python
# Continuing from the previous section...

# Create a new Repository object that holds the file path to the repository and the four
# top-level role objects (Root, Targets, Release, Timestamp). Metadata files are created when
# repository.write() is called.  The repository directory is created if it does not exist.
repository = create_new_repository("path/to/repository/")

# The Repository instance, ‘repository’, initially contains top-level Metadata objects.
# Add one of the public keys, created in the previous section, to the root role.  Metadata is
# considered valid if it is signed by the public key’s corresponding private key
repository.root.add_key(public_root_key)

# Add a second public key to the root role.  Although previously generated and saved to a file,
# the second public key must be imported before it can added to a role.
public_root_key2 = import_rsa_publickey_from_file("path/to/root_key2.pub")
repository.root.add_key(public_root_key2)

# Threshold for each role defaults to 1.   Users may change the threshold value, but libtuf.py
# validates thresholds and signatures and warns users.  Set the threshold of the root role to 2,
# which means the root metadata file is considered valid if it contains at least 2 valid 
# signatures.
repository.root.threshold = 2
private_root_key2=import_rsa_privatekey_from_file("path/to/root_key2",password="pw")

# Load the root signing keys to the repository, which write() uses to sign the root metadata.
# The load_signing_key() method SHOULD warn when the key is NOT explicitly allowed to
#  sign for it.
repository.root.load_signing_key(private_root_key)
repository.root_load_signing_key(private_root_key2)

try:
  repository.write()
# An exception is raised here by write() because the other top-level roles (targets, release,
# and timestamp) have not been configured with keys.
except tuf.Error, e:
  print e 
Not enough signatures for '/home/santiago/Documents/o2013/NYU/TUF/repo-tools/repo-real/metadata.staged/root.txt'

# In the next section, update the other top-level roles and create a repository with valid metadata
```

#### Create Timestamp, Release, Targets

```python
# Continuing from the previous section . . .

# Generate keys for the remaining top-level roles.  The root keys have been set above.
# The password argument may be omitted if a password prompt is needed. 
generate_and_write_rsa_keypair("path/to/targets_key", password="pw")
generate_and_write_rsa_keypair("path/to/release_key", password="pw")
generate_and_write_rsa_keypair("path/to/timestamp_key", password="pw")

# Add the public keys of the remaining top-level roles.
repository.targets.add_key(import_rsa_publickey_from_file("path/to/targets_key.pub"))
repository.release.add_key(import_rsa_publickey_from_file("path/to/release_key.pub"))
repository.timestamp.add_key(import_rsa_publickey_from_file("path/to/timestamp_key.pub"))

# Import the signing keys of the remaining top-level roles.  Prompt for passwords.
private_targets_key = import_rsa_privatekey_from_file("path/to/targets_key")
Enter a password for the RSA key:
Confirm:
private_release_key = import_rsa_privatekey_from_file("path/to/release_key")
Enter a password for the RSA key:
Confirm:
private_timestamp_key = import_rsa_privatekey_from_file("path/to/timestamp_key")
Enter a password for the RSA key:
Confirm:

# Load the signing keys of the remaining roles so that valid signatures are generated when
# repository.write() is called.
repository.targets.load_signing_key(private_targets_key)
repository.release.load_signing_key(private_release_key)
repository.timestamp.load_signing_key(private_timestamp_key)

# Optionally set the expiration date of the timestamp role.  By default, roles are set to expire
# as follows:  root(1 year), targets(3 months), release(1 week), timestamp(1 day).
repository.timestamp.expiration = "2014-10-28 12:08:00"

# Write all metadata to “path/to/repository/metadata/”
# The common case is to crawl the filesystem for all roles in
# “path/to/repository/metadata/targets/”.
repository.write()
```

### Targets

#### Add Target Files
```python

```
