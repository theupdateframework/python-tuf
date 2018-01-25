# Quickstart #

Note: A work in progress.  Only examples are given here, for now.

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
