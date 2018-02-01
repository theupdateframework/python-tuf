# CLI examples #

Note: This is a work in progress and subject to change.

## Create a repository ##

Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The Targets role does not sign for
any targets nor does it delegate trust to any roles.

```Bash
$ repo.py --init
```

Optionally, the repository can be written to a specified location.
```Bash
$ repo.py --init --path </path/to/repo>
```

Note:  The default top-level key files created with --init are saved to disk
encrypted, with a default password of 'pw'.  Instead of using the default
password, the user can enter one on the command line or be prompted
for it via password masking.
```Bash
$ repo.py --init --pw my_password
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

Similar to the --init case, the repository location can be specified.
```Bash
$ repo.py --add <foo.tar.gz> --path </path/to/my_repo>
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
$ repo.py --clean --path </path/to/dirty/repo>
```
(--clean by itself removes TUF files from the current working directory.)
