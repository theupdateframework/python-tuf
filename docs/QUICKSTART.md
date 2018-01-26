# Quickstart #

Note: This is a work in progress.  Only examples are given here, for now.
The following is a workflow example in four steps:

**Step (1) - Create a repo**
```Bash
$ repo.py --init
```

**Step (2) - Add a target file**
```Bash
$ repo.py --add foo.tar.gz
```

**Step (3) - Serve the repo**
```Bash
$ cd "repo/"
$ python -m SimpleHTTPServer 8001
```

**Step (4) - Fetch a target file from repo**
```Bash
$ cd "client/"
$ client.py --repo http://localhost:8001 foo.tar.gz
```


See [CLI.md](CLI.md) for more examples.  A [tutorial](../tuf/README.md) is also
available, and designed for users that want more control over the creation
process.
