# Quickstart #

Note: A work in progress.  Only examples are given here, for now.

A full working example in four steps.

(1)
```Bash
$ repo.py --init
```

(2)
```Bash
$ repo.py --add foo.tar.gz
```

(3)
```Bash
$ cd "repository/"
$ python -m SimpleHTTPServer 8001
```

(4)
```Bash
$ cd "client/"
$ client.py --repo http://localhost:8001 foo.tar.gz
```


## Create a TUF repository.

Examples:

Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The Targets role does not sign for
any targets nor does it delegate trust to any roles.

```Bash
$ repo.py --init
```

Create a TUF repository at `./repository`.
```Bash
$ repo.py --init repository/
```

Create a TUF repository in the current working directory.  A cryptographic key
is *not* created nor set for each top-level role.
```Bash
$ repo.py --init --bare True
```

```Bash
$ repo.py --init --consistent_snapshots True
```
