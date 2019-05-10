# Rollback Attack
Here an attacker tries to present the client with a file version that he has already seen, i.e. it tries to trick the client to install
files older than those the client knows about(which might be vulnerable and can be exploited later by the attacker). The client doesn't accept the metadata older than those what he has previously trusted, so it will not 
accept the download and won't rollback.

## Walkthrough
Here we backup the latest timestamp.json metadata file on the server side, and then upgrade the version of the timestamp and make the 
client update its repository accordingly. After this, an attacker replaces the new timestamp.json with the backed up (older verison) of that same file, 
and tries to trick the client to downgrade its version of timestamp.json, where it'll throw `ReplayedMetadataError` error and thereby reject the download.

Initially the client is on the latest version of the repository, on the server side, make a backup of timestamp.json-

```Bash
$ cp timestamp.json /tmp
```
Generate a new version of timestamp.json by,

```Bash
# (assuming password for private keys is 'password')
$ python
>>> from tuf.repository_tool import *
>>> repository = load_repository('repository')
>>> repository.timestamp.version
3
>>> repository.timestamp.version = 4 #(upgrade the timestamp.json version)
>>> repository.dirty_roles()
Dirty roles: ['timestamp']
>>> private_timestamp_key=  import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for an encrypted RSA file 'keystore/timestamp_key': password
>>> repository.timestamp.load_signing_key(private_timestamp_key)
>>> repository.write('timestamp')
>>> exit()
```
```Bash
$ cp repository/metadata.staged/* repository/metadata
```

Now the client tries to update its top level metadata by, 

```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
It gets the latest version of timestamp.json successfully.

Now at server side, replace the timestamp.json with the backed up version of it, 

```Bash
$ cp /tmp/timestamp.json repository/metadata/
```

Again at client side, when trying to make a request for the file, 

```Bash
$ client.py --repo http://localhost:8001 --verbose 3 file2.txt
```
We get the following error, as the metadata being served is older than what the client has previously seen.

```Bash
Update failed from http://localhost:8001/metadata/timestamp.json.
tuf.exceptions.ReplayedMetadataError: Downloaded 'timestamp' is older (2) than the version currently installed (4).
Failed to update 'timestamp.json' from all mirrors: {'http://localhost:8001/metadata/timestamp.json': ReplayedMetadataError()}
Error: No working mirror was found: 'localhost:8001': ReplayedMetadataError()
```

Now restore the latest timestamp.json at the server side, 

```Bash
$ cp repository/metadata.staged/timestamp.json repository/metadata
```
  
  
