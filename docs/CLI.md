# Command-Line Interface #

The TUF command-line interface (CLI) requires a full
[TUF installation](INSTALLATION.rst).  Be sure to include the installation of
extra dependencies and C extensions (
```pip install securesystemslib[crypto,pynacl]```).

The use of the CLI is documented with examples below.

----
# Basic Examples #

## Create a repository ##

Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The written Targets metadata does
not sign for any targets, nor does it delegate trust to any roles.  The
`--init` call will also set up a client directory.  By default, these
directories will be `./tufrepo` and `./tufclient`.

```Bash
$ repo.py --init
```

Optionally, the repository can be written to a specified location.
```Bash
$ repo.py --init --path </path/to/repo_dir>
```

The default top-level key files created with `--init` are saved to disk
encrypted, with a default password of 'pw'.  Instead of using the default
password, the user can enter one on the command line for each top-level role.
These optional command-line options also work with other CLI actions (e.g.,
repo.py --add).
```Bash
$ repo.py --init [--targets_pw, --root_pw, --snapshot_pw, --timestamp_pw]
```



Create a bare TUF repository in the current working directory.  A cryptographic
key is *not* created nor set for each top-level role.
```Bash
$ repo.py --init --bare
```



Create a TUF repository with [consistent
snapshots](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#7-consistent-snapshots)
enabled, where target filenames have their hash prepended (e.g.,
`<hash>.README.txt`), and metadata filenames have their version numbers
prepended (e.g., `<hash>.snapshot.json`).
```Bash
$ repo.py --init --consistent
```



## Add a target file ##

Copy a target file to the repo and add it to the Targets metadata (or the
Targets role specified in --role).  More than one target file, or directory,
may be specified in --add.  The --recursive option may be toggled to also
include files in subdirectories of a specified directory.  The Snapshot
and Timestamp metadata are also updated and signed automatically, but this
behavior can be toggled off with --no_release.
```Bash
$ repo.py --add <foo.tar.gz> <bar.tar.gz>
$ repo.py --add </path/to/dir> [--recursive]
```

Similar to the --init case, the repository location can be chosen.
```Bash
$ repo.py --add <foo.tar.gz> --path </path/to/my_repo>
```



## Remove a target file ##

Remove a target file from the Targets metadata (or the Targets role specified
in --role).  More than one target file or glob pattern may be specified in
--remove.  The Snapshot and Timestamp metadata are also updated and signed
automatically, but this behavior can be toggled off with --no_release.

```Bash
$ repo.py --remove <glob_pattern> ...
```

Examples:

Remove all target files, that match `foo*.tgz,` from the Targets metadata.
```Bash
$ repo.py --remove "foo*.tgz"
```

Remove all target files from the `my_role` metadata.
```Bash
$ repo.py --remove "*" --role my_role --sign tufkeystore/my_role_key
```


## Generate key ##
Generate a cryptographic key.  The generated key can later be used to sign
specific metadata with `--sign`.  The supported key types are: `ecdsa`,
`ed25519`, and `rsa`.  If a keytype is not given, an Ed25519 key is generated.

If adding a top-level key to a bare repo (i.e., repo.py --init --bare),
the filenames of the top-level keys must be "root_key," "targets_key,"
"snapshot_key," "timestamp_key."  The filename can vary for any additional
top-level key.
```Bash
$ repo.py --key
$ repo.py --key <keytype>
$ repo.py --key <keytype> [--path </path/to/repo_dir> --pw [my_password],
  --filename <key_filename>]
```

Instead of using a default password, the user can enter one on the command
line or be prompted for it via password masking.
```Bash
$ repo.py --key ecdsa --pw my_password
```

```Bash
$ repo.py --key rsa --pw
Enter a password for the RSA key (...):
Confirm:
```



## Sign metadata ##
Sign, with the specified key(s), the metadata of the role indicated in --role.
The Snapshot and Timestamp role are also automatically signed, if possible, but
this behavior can be disabled with --no_release.
```Bash
$ repo.py --sign </path/to/key> ... [--role <rolename>, --path </path/to/repo>]
```

For example, to sign the delegated `foo` metadata:
```Bash
$ repo.py --sign </path/to/foo_key> --role foo
```



## Trust keys ##

The Root role specifies the trusted keys of the top-level roles, including
itself.  The --trust command-line option, in conjunction with --pubkeys and
--role, can be used to indicate the trusted keys of a role.

```Bash
$ repo.py --trust --pubkeys --role
```

For example:
```Bash
$ repo.py --init --bare
$ repo.py --trust --pubkeys tufkeystore/my_key.pub tufkeystore/my_key_too.pub
  --role root
```



### Distrust keys ###

Conversely, the Root role can discontinue trust of specified key(s).

Example of how to discontinue trust of a key:
```Bash
$ repo.py --distrust --pubkeys tufkeystore/my_key_too.pub --role root
```



## Delegations ##

Delegate trust of target files from the Targets role (or the one specified in
--role) to some other role (--delegatee).  --delegatee is trusted to sign for
target files that match the delegated glob pattern(s).  The --delegate option
does not create metadata for the delegated role, rather it updates the
delegator's metadata to list the delegation to --delegatee.  The Snapshot and
Timestamp metadata are also updated and signed automatically, but this behavior
can be toggled off with --no_release.

```Bash
$ repo.py --delegate <glob pattern> ... --delegatee <rolename> --pubkeys
</path/to/pubkey.pub> ... [--role <rolename> --terminating --threshold <X>
--sign </path/to/role_privkey>]
```

For example, to delegate trust of `foo*.gz` packages to the `foo` role:

```
$ repo.py --delegate "foo*.tgz" --delegatee foo --pubkeys tufkeystore/foo.pub
```



## Revocations ##

Revoke trust of target files from a delegated role (--delegatee).  The
"targets" role performs the revocation if --role is not specified.  The
--revoke option does not delete the metadata belonging to --delegatee, instead
it removes the delegation to it from the delegator's (or --role) metadata.  The
Snapshot and Timestamp metadata are also updated and signed automatically, but
this behavior can be toggled off with --no_release.


```Bash
$ repo.py --revoke --delegatee <rolename> [--role <rolename>
--sign </path/to/role_privkey>]
```



## Verbosity ##

Set the verbosity of the logger (2, by default).  The lower the number, the
greater the verbosity.  Logger messages are saved to `tuf.log` in the current
working directory.
```Bash
$ repo.py --verbose <0-5>
```



## Clean ##

Delete the repo in the current working directory, or the one specified with
`--path`.  Specifically, the `tufrepo`, `tufclient`, and `tufkeystore`
directories are deleted.

```Bash
$ repo.py --clean
$ repo.py --clean --path </path/to/dirty/repo>
```
----








# Further Examples #

## Basic Update Delivery ##

Steps:

(1) initialize a repo.

(2) delegate trust of target files to another role.

(3) add a trusted file to the delegated role.

(4) fetch the trusted file from the delegated role.

```Bash
Step (1)
$ repo.py --init

Step (2)
$ repo.py --key ed25519 --filename mykey
$ repo.py --delegate "README.*" --delegatee myrole --pubkeys tufkeystore/mykey.pub
$ repo.py --sign tufkeystore/mykey --role myrole
Enter a password for the encrypted key (tufkeystore/mykey):
$ echo "my readme text" > README.txt

Step (3)
$ repo.py --add README.txt --role myrole --sign tufkeystore/mykey
Enter a password for the encrypted key (tufkeystore/mykey):
```

Serve the repo
```Bash
$ cd tufrepo/
$ python -m SimpleHTTPServer 8001
```

If running python 3:
```Bash
$ python3 -m http.server 8001
```

```Bash
Step (4)
$ client.py --repo http://localhost:8001 README.txt
$ tree .
.
├── tuf.log
├── tufrepo
│   └── metadata
│       ├── current
│       │   ├── 1.root.json
│       │   ├── myrole.json
│       │   ├── root.json
│       │   ├── snapshot.json
│       │   ├── targets.json
│       │   └── timestamp.json
│       └── previous
│           ├── 1.root.json
│           ├── root.json
│           ├── snapshot.json
│           ├── targets.json
│           └── timestamp.json
└── tuftargets
    └── README.txt

    5 directories, 13 files
```


## Correcting a Key ##
The filename of the top-level keys must be "root_key," "targets_key,"
"snapshot_key," and "root_key."  The filename can vary for any additional
top-level key.

Steps:

(1) initialize a repo containing default keys for the top-level roles.
(2) distrust the default key for the root role.
(3) create a new key and trust its use with the root role.
(4) sign the root metadata file.

```Bash
Step (1)
$ repo.py --init

Step (2)
$ repo.py --distrust --pubkeys tufkeystore/root_key.pub --role root

Step (3)
$ repo.py --key ed25519 --filename root_key
$ repo.py --trust --pubkeys tufkeystore/root_key.pub --role root

Step (4)
$ repo.py --sign tufkeystore/root_key --role root
Enter a password for the encrypted key (tufkeystore/root_key):
```


## More Update Delivery ##

Steps:

(1) create a bare repo.

(2) add keys to the top-level roles.

(3) delegate trust of particular target files to another role X, where role X
has a signature threshold 2 and is marked as a terminating delegation.  The
keys for role X and Y should be created prior to performing the delegation.

(4) Delegate from role X to role Y.

(5) have role X sign for a file also signed by the Targets role, to demonstrate
the expected file that should be downloaded by the client.

(6) perform an update.

(7) halt the server, add README.txt to the Targets role, restart the server,
and fetch the Target's role README.txt.

(8) Add LICENSE to 'role_y' and demonstrate that the client must not fetch it
because 'role_x' is a terminating delegation (and hasn't signed for it).

```Bash
Steps (1) and (2)
$ repo.py --init --consistent --bare
$ repo.py --key ed25519 --filename root_key
$ repo.py --trust --pubkeys tufkeystore/root_key.pub --role root
$ repo.py --key ecdsa --filename targets_key
$ repo.py --trust --pubkeys tufkeystore/targets_key.pub --role targets
$ repo.py --key rsa --filename snapshot_key
$ repo.py --trust --pubkeys tufkeystore/snapshot_key.pub --role snapshot
$ repo.py --key ecdsa --filename timestamp_key
$ repo.py --trust --pubkeys tufkeystore/timestamp_key.pub --role timestamp
$ repo.py --sign tufkeystore/root_key --role root
Enter a password for the encrypted key (tufkeystore/root_key):
$ repo.py --sign tufkeystore/targets_key --role targets
Enter a password for the encrypted key (tufkeystore/targets_key):
```

```Bash
Steps (3) and (4)
$ repo.py --key ed25519 --filename key_x
$ repo.py --key ed25519 --filename key_x2

$ repo.py --delegate "README.*" "LICENSE" --delegatee role_x --pubkeys
  tufkeystore/key_x.pub tufkeystore/key_x2.pub --threshold 2 --terminating
$ repo.py --sign tufkeystore/key_x tufkeystore/key_x2 --role role_x

$ repo.py --key ed25519 --filename key_y

$ repo.py --delegate "README.*" "LICENSE" --delegatee role_y --role role_x
  --pubkeys tufkeystore/key_y.pub --sign tufkeystore/key_x tufkeystore/key_x2

$ repo.py --sign tufkeystore/key_y --role role_y
```

```Bash
Steps (5) and (6)
$ echo "role_x's readme" > README.txt
$ repo.py --add README.txt --role role_x --sign tufkeystore/key_x tufkeystore/key_x2
```

Serve the repo
```Bash
$ cd tufrepo/
$ python -m SimpleHTTPServer 8001
```

If running python 3:
```Bash
$ python3 -m http.server 8001
```

Fetch the role x's README.txt
```Bash
$ client.py --repo http://localhost:8001 README.txt
$ cat tuftargets/README.txt
role_x's readme
```


```Bash
Step (7)
halt the server...

$ echo "Target role's readme" > README.txt
$ repo.py --add README.txt

restart the server...
```

```Bash
$ rm -rf tuftargets/ tuf.log
$ client.py --repo http://localhost:8001 README.txt
$ cat tuftargets/README.txt
Target role's readme
```

```Bash
Step (8)
$ echo "role_y's license" > LICENSE
$ repo.py --add LICENSE --role role_y --sign tufkeystore/key_y
```

```Bash
$ rm -rf tuftargets/ tuf.log
$ client.py --repo http://localhost:8001 LICENSE
Error: 'LICENSE' not found.
```
