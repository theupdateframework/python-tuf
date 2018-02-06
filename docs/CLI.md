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

Copy a target file to the repo and add it to Targets metadata.  More than one
target file, or directory, may be specified with --add.  The --recursive option
may be selected to also include files in subdirectories of a specified
directory.
```Bash
$ repo.py --add <foo.tar.gz> <bar.tar.gz>
$ repo.py --add </path/to/dir> [--recursive]
```

Similar to the --init case, the repository location can be specified.
```Bash
$ repo.py --add <foo.tar.gz> --path </path/to/my_repo>
```



# Generate key ##
```Bash
$ repo.py --key
$ repo.py --key <keytype>
$ repo.py --key <keytype> --path </path/to/repo> --pw [my_password], --filename
```



## Sign metadata ##
Sign, using the specified key argument, the metadata of the role indicated by
--role.  If no key argument or --role is given, the Targets role or its key is
used.  The Snapshot and Timestamp role are also automatically signed, if
possible.
```Bash
$ repo.py --sign
$ repo.py --sign </path/to/key>
$ repo.py --sign </path/to/key> [--role <rolename>]
$ repo.py --sign </path/to/key> [--role <rolename>, --path </path/to/repo>]
```

For example, to sign a new Timestamp:
```Bash
$ repo.py --sign /path/to/timestamp_key --role timestamp
```

Note: In the future, the user might be given the option of disabling automatic
signing of Snapshot and Timestamp metadata.  Also, only ECDSA keys are
presently supported, but other key types will be added.



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
