# Mix And Match Attack

An attacker tries to present client with a view of the repository that contains files that never existed together. In doing so, 
the client might be tricked to install some vulnerable files (it might be the outdated versions of the trusted files) that can later be exploited by the attacker. 

## Walkthrough
In order to simulate this attack, an attacker tries to trick the client in downloading the 
files that never existed together at the same time on the repository.
So for this, given the client is on a certain version, when the repository updates its version, the attacker replaces one of the files
with its outdated version, such that when the client requests for an update, it installs latest version of the repository with the older version of that file on the client. But as an attacker won't be able to 
change the trusted TUF metadata file, it'll throw `BadHashError` and the client will reject the download.

Initially the client has the latest version of the repository, so now at server side we try to make some changes and update the repository.

Make a backup of the older version of file1.txt,
```Bash
$ mv file1.txt file1_v1.txt
```

We change file1.txt, which updates its version as well, 
```Bash
# (assuming that we gave password 'password' while generating the private keys)
>>> python
>>> import os
>>> from tuf.repository_tool import *
>>> repository = load_repository("repository/")
>>> list_of_targets = ['file1.txt']
>>> repository.targets.add_targets(list_of_targets)
>>> private_targets_key = import_rsa_privatekey_from_file("keystore/targets_key")
Enter a password for an encrypted RSA file 'keystore/targets_key': ‘password’
>>> repository.targets.load_signing_key(private_targets_key)
>>> private_snapshot_key = import_rsa_privatekey_from_file("keystore/snapshot_key")
Enter a password for an encrypted RSA file 'keystore/snapshot_key': ‘password’
>>> repository.targets.load_signing_key(private_snapshot_key)
>>> private_timestamp_key = import_rsa_privatekey_from_file("keystore/timestamp_key")
Enter a password for an encrypted RSA file 'keystore/timestamp_key':  ‘password’
>>> repository.targets.load_signing_key(private_timestamp_key)
>>> repository.dirty_roles()
Dirty roles: ['snapshot', 'targets', 'timestamp']

# (or mark dirty roles manually by (
# >>> repository.mark_dirty(['snapshot', 'targets', 'timestamp']))

>>> repository.writeall()
```

```Bash
$ cp -r "repository/metadata.staged/" "repository/metadata/"
```
Now replace file1.txt with the backed up older version, such that while the repository has upgraded to a newer version, file1.txt is still on older version,
```Bash
$ mv file1.txt file1.txt.v_2
$ mv file1_v1.txt file1.txt
```
Now, at the client side, we request for fresh update by,

```Bash
$ rm -rf "tuftargets/" "tufrepo/metadata/current/timestamp.json" "tufrepo/metadata/current/snapshot.json"
```
```Bash
$ client.py --repo http://localhost:8001 --verbose 5 file1.txt
```
We get the follwoing error because hash doens't match for the file1.txt 
```Bash
Error: No working mirror was found:
'localhost:8001': BadHashError('250afad6cb1013fd0b1fc90f97285745353d7e370a8aee5fe522bcc9ddb23e05', '3e72d6f1435cf363189de2c24a2cac5cf9db6efc1b21421261cddd9dd1120b18')
```


