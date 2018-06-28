# Quickstart #

The CLI requires a few dependencies and C extensions that can be installed with
`pip install securesystemslib[crypto,pynacl]`.

----
The following is a basic workflow in four steps:

**Step (1)** - Initialize a repo.  The `tufrepo`, `tufkeystore`, and
`tufclient` directories are created in the current working directory.
```Bash
$ repo.py --init
```

**Step (2)** - Add a target file to the repo.  The file size and hashes of
the target file are also written to the Targets metadata file.
```Bash
$ echo 'Test file' > testfile
$ repo.py --add testfile
$ tree tufrepo/
tufrepo/
├── metadata
│   ├── 1.root.json
│   ├── root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
├── metadata.staged
│   ├── 1.root.json
│   ├── root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
└── targets
    └── testfile

    3 directories, 11 files
```

**Step (3)** - Serve the repo
```Bash
$ cd "tufrepo/"
$ python -m SimpleHTTPServer 8001

or with Python 3...
$ python3 -m http.server 8001
```

**Step (4)** - Fetch a target file from the repo.  The client downloads
any required metadata and the requested target file.
```Bash
$ cd "tufclient/"
$ client.py --repo http://localhost:8001 testfile
$ tree
.
├── tufrepo
│   └── metadata
│       ├── current
│       │   ├── 1.root.json
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
    └── testfile

    5 directories, 11 files
```
----

See [CLI.md](CLI.md) and [CLI_EXAMPLES.md](CLI_EXAMPLES.md) to learn about the
other supported CLI options.  A [tutorial](TUTORIAL.md) is also available, and
intended for users that want more control over the repo creation process.
