# Quickstart #

Note: This is a work in progress and subject to change.

The following is a basic workflow in four steps:

**Step (1)** - Initialize an empty repo
```Bash
$ repo.py --init
```

**Step (2)** - Add a target file to the repo
```Bash
$ echo 'Test file' > testfile
$ repo.py --add testfile
```

**Step (3)** - Serve the repo
```Bash
$ cd "tufrepo/"
$ python -m SimpleHTTPServer 8001

or with Python 3...
$ python3 -m http.server 8001
```

**Step (4)** - Fetch a target file from the repo
```Bash
$ cd "tufclient/"
$ client.py --repo http://localhost:8001 testfile
```


See [CLI.md](CLI.md) and [CLI_EXAMPLES.md](CLI_EXAMPLES.md) to learn about the
other supported CLI options.  A [tutorial](TUTORIAL.md) is also available, and
intended for users that want more control over the repo creation process.
