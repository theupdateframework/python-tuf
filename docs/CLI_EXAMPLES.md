# CLI Usage Examples #

This document contains a few examples of creating repositories with the CLI.
The sections below correspond with a different example, and each begins with an
outline of the steps to be followed by the user.

## A basic example ##

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


## An example of replacing a top-level key ##
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


## A more complicated example ##

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

(8) Add LICENSE to 'role_y' and demonstate that the client must not fetch it
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
