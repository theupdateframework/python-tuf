# CLI examples #

Note: This is a work in progress and subject to change.

## Create a repository ##

Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The Targets role does not sign for
any targets nor does it delegate trust to any roles.

```Bash
$ repo.py --init
```
Note: Support for arbitrary repo paths will be added in the near future.
`$ repo.py --init --path </path/to/repo>`

By default, `pw` is used to encrypt the top-level key files created with
--init.  Instead, the user can enter a password on the command line, or be
prompted for one.
```Bash
$ repo.py --init --pw my_pw
```

```Bash
$ repo.py --init --pw
Enter a password for the top-level role keys:
Confirm:
```


Create a TUF repository in the current working directory.  A cryptographic key
is *not* created nor set for each top-level role.
```Bash
$ repo.py --init --bare
```



Create a TUF repository with [consistent
snapshots](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#7-consistent-snapshots)
enabled.  If enabled, all target filenames have their hash prepended.
```Bash
$ repo.py --init --consistent_snapshot
```



## Add a target file ##

More than one target file may be specified.
```Bash
$ repo.py --add <foo.tar.gz> <bar.tar.gz>
```
Note: Support for directories will be added in the near future.
`$ repo.py --add </path/to/dir> [--recursive]`


## Verbosity ##

Set the verbosity of the logger (2, by default).  Logger messages are saved to
`tuf.log` in the current working directory.
```Bash
$ repo.py --verbose <0-5>
```

## Clean ##

Remove the files created via `repo.py --init`.
```Bash
$ repo.py --clean
```
