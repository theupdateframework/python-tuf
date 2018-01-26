# CLI examples #

Note: This is a work in progress.  Only examples are given here, for now.

## Create a repository ##

* Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The Targets role does not sign for
any targets nor does it delegate trust to any roles.

```Bash
$ repo.py --init
```

---
* Create a TUF repository at `./repo`.
```Bash
$ repo.py --init repo/
```

---
* Create a TUF repository in the current working directory.  A cryptographic key
is *not* created nor set for each top-level role.
```Bash
$ repo.py --init --bare
```

---
* Create a TUF repository with [consistent
snapshots](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#7-consistent-snapshots)
enabled.  If enabled, all target filenames have their hash prepended.
```Bash
$ repo.py --init --consistent_snapshots
```
