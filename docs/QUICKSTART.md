# Quickstart #

Note: This is a work in progress and subject to change.

The following is a basic workflow in four steps:

**Step (1)** - Create a repo
```Bash
$ repo.py --init
```

**Step (2)** - Add a target file
```Bash
$ repo.py --add foo.tar.gz
```

**Step (3)** - Serve the repo
```Bash
$ cd "tufrepo/"
$ python -m SimpleHTTPServer 8001

or with Python 3...
$ python3 -m http.server 8001
```

**Step (4)** - Retrieve a target file
```Bash
$ cd "tufclient/"
$ client.py --repo http://localhost:8001 foo.tar.gz
```


See [CLI.md](CLI.md) for more examples.  A [tutorial](TUTORIAL.md) is also
available, and intended for users that want more control over the creation
process.
