# CLI Examples #

## Basic example ##
(1) initialize a repo (2) delegate trust of target files to another role (3)
add a trusted file to the delegated role (4) fetch the trusted file from the
delegated role.

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

```Bash
$ repo.py --init
$ repo.py --distrust --pubkeys tufkeystore/root_key.pub --role root
$ repo.py --key ed25519 --filename root_key
$ repo.py --trust --pubkeys tufkeystore/root_key.pub --role root
$ repo.py --sign tufkeystore/root_key --role root
Enter a password for the encrypted key (tufkeystore/root_key):
```


## A more complicated example ##
(1) create a bare repo (2) add keys to the top-level roles (3) delegate
trust of particular target files to another role X, where role X has a
signature threshold >1 and is marked as a terminating delegation (4) create a
subdelegation Y (5) have role X sign for a file also trusted and signed by role Y, to
demonstrate the expected file that should be downloaded by clients (6)
perform an update (7) revoke Y (8) show update behavior after Y's revocation.

```Bash
$ repo.py --init --bare



```
