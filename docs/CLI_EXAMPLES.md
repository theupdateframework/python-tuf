# CLI Examples #

## Basic example ##
(1) initialize a repo.

(2) delegate trust of target files to another role.

(3) add a trusted file to the delegated role.

(4) fetch the trusted file from the delegated role.

```Bash
$ repo.py --init
$ repo.py --key ed25519 --filename mykey
$ repo.py --delegate "README.*" --delegatee myrole --pubkeys tufkeystore/mykey.pub
$ repo.py --sign tufkeystore/mykey --role myrole
Enter a password for the encrypted key (tufkeystore/mykey):
$ echo "my readme text" > README.txt
$ repo.py --add README.txt --role myrole --sign tufkeystore/mykey
Enter a password for the encrypted key (tufkeystore/mykey):
```

Serve the repo
```Bash
$ cd tufrepo/
$ python -m SimpleHTTPServer 8001
```

Fetch the repo's README.txt
```Bash
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


## Replace a top-level key ##
Note: The top-level keys should be named "root_key," "targets_key," "snapshot_key,"
and "root_key."  Additional top-level keys may be named anything, and must
be used with --sign.

```Bash
$ repo.py --init
$ repo.py --distrust --pubkeys tufkeystore/root_key.pub --role root
$ repo.py --key ed25519 --filename root_key
$ repo.py --trust --pubkeys tufkeystore/root_key.pub --role root
$ repo.py --sign tufkeystore/root_key --role root
Enter a password for the encrypted key (tufkeystore/root_key):
```


## A more complicated example ##
(1) create a bare repo.

(2) add keys to the top-level roles.

(3) delegate trust of particular target files to another role X, where role X
has a signature threshold 2 and is marked as a terminating delegation.

(4) Delegate from role X to role Y.

(5) have role X sign for a file also signed by the Targets role, to demonstrate
the expected file that should be downloaded by the client.

(6) perform an update.

(7) halt the server, add README.txt to the Targets role, restart server, and
fetch the Target's role README.txt.

(8) Add LICENSE to 'yrole' and demonstate that the client must not fetch it
because xrole is a terminating delegation (and hasn't signed for it).

(1) and (2)
```Bash
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

(3) and (4)
```Bash
$ repo.py --delegate "README.*" "LICENSE" --delegatee xrole --pubkeys
  tufkeystore/xkey.pub tufkeystore/xkey2.pub --threshold 2 --terminating
$ repo.py --sign tufkeystore/xkey tufkeystore/xkey2 --role xrole
$ repo.py --key ed25519 --filename ykey
$ repo.py --delegate "README.*" "LICENSE" --delegatee yrole --role xrole
  --pubkeys tufkeystore/ykey.pub --sign tufkeystore/xkey tufkeystore/xkey2
$ repo.py --sign tufkeystore/ykey --role yrole
```

(5) and (6)
```Bash
$ echo "xrole's readme" > README.txt
$ repo.py --add README.txt --role xrole --sign tufkeystore/xkey tufkeystore/xkey2
```

Serve the repo
```Bash
$ cd tufrepo/
$ python -m SimpleHTTPServer 8001
```

Fetch the xrole's README.txt
```Bash
$ client.py --repo http://localhost:8001 README.txt
$ cat tuftargets/README.txt
xrole's readme
```

(7)

```Bash
halt server...

$ echo "Target role's readme" > README.txt
$ repo.py --add README.txt

restart server...
```

```Bash
$ rm -rf tuftargets/ tuf.log
$ client.py --repo http://localhost:8001 README.txt
$ cat tuftargets/README.txt
Target role's readme
```

(8)
```Bash
$ echo "yrole's license" > LICENSE
$ repo.py --add LICENSE --role yrole --sign tufkeystore/ykey
```

```Bash
$ rm -rf tuftargets/ tuf.log
$ client.py --repo http://localhost:8001 LICENSE
Traceback (most recent call last):
...
tuf.exceptions.UnknownTargetError: 'LICENSE' not found.
```
