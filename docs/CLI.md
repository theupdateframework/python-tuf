# CLI #

Note: This is a work in progress and subject to change.  See
[CLI_EXAMPLES.md](CLI_EXAMPLES.md) for more complex examples.

## Create a repository ##

Create a TUF repository in the current working directory.  A cryptographic key
is created and set for each top-level role.  The written Targets metadata does
not sign for any targets, nor does it delegate trust to any roles.

```Bash
$ repo.py --init
```

Optionally, the repository can be written to a specified location.
```Bash
$ repo.py --init --path </path/to/repo_dir>
```

Note:  The default top-level key files created with `--init` are saved to disk
encrypted, with a default password of 'pw'.  Instead of using the default
password, the user can enter one on the command line for each top-level role.
These optional command-line options also work with other CLI actions (e.g.,
repo.py --add).
```Bash
$ repo.py --init [--targets_pw, --root_pw, --snapshot_pw, --timestamp_pw]
```



Create a TUF repository in the current working directory.  A cryptographic key
is *not* created nor set for each top-level role.
```Bash
$ repo.py --init --bare
```



Create a TUF repository with [consistent
snapshots](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md#7-consistent-snapshots)
enabled, where target filenames have their hash prepended (e.g.,
`<hash>.README.txt`), and metadata filenames have their version numbers
prepended (e.g., `<hash>.snapshot.json`).
```Bash
$ repo.py --init --consistent
```




## Add a target file ##

Copy a target file to the repo and add it to the Targets metadata (or the
Targets role specified in --role).  More than one target file, or directory,
may be specified in --add.  The --recursive option may be toggled to also
include files in subdirectories of a specified directory.
```Bash
$ repo.py --add <foo.tar.gz> <bar.tar.gz>
$ repo.py --add </path/to/dir> [--recursive]
```

Similar to the --init case, the repository location can be chosen.
```Bash
$ repo.py --add <foo.tar.gz> --path </path/to/my_repo>
```




## Remove a target file ##

Remove a target file from the Targets metadata (or the Targets role specified
in --role).  More than one target file or glob pattern may be specified in
--remove.

```Bash
$ repo.py --remove <glob_pattern> ...
```

Examples:

Remove all target files, that match `foo*.tgz,` from the Targets metadata.
```Bash
$ repo.py --remove "foo*.tgz"
```

Remove all target files from the `my_role` metadata.
```Bash
$ repo.py --remove "*" --role my_role --sign tufkeystore/my_role_key
```


## Generate key ##
Generate a cryptographic key.  The generated key can later be used to sign
specific metadata with `--sign`.  The supported key types are: `ecdsa`,
`ed25519`, and `rsa`.  If a keytype is not given, an Ed25519 key is generated.
Note: If adding a top-level key to a bare repo (i.e., repo.py --init --bare),
the top-level keys should be named "root_key," "targets_key," "snapshot_key,"
"timestamp_key."  Additional top-level keys may be named anything, and must be
used with --sign.
```Bash
$ repo.py --key
$ repo.py --key <keytype>
$ repo.py --key <keytype> [--path </path/to/repo_dir> --pw [my_password],
  --filename <key_filename>]
```

Instead of using a default password, the user can enter one on the command
line or be prompted for it via password masking.
```Bash
$ repo.py --key ecdsa --pw my_password
```

```Bash
$ repo.py --key rsa --pw
Enter a password for the RSA key (...):
Confirm:
```



## Trust keys ##

The Root role specifies the trusted keys of the top-level roles, including
itself.  The --trust command-line option, in conjunction with --pubkeys and
--role, can be used to indicate the trusted keys of a role.

```Bash
$ repo.py --trust --pubkeys --role
```

For example:
```Bash
$ repo.py --init --bare
$ repo.py --trust --pubkeys tufkeystore/my_key.pub tufkeystore/my_key_too.pub
  --role root
```

### Distrust keys ###

Conversely, the Root role can discontinue trust of specified key(s).

Example of how to discontinue trust of a key:
```Bash
$ repo.py --distrust --pubkeys tufkeystore/my_key_too.pub --role root
```



## Sign metadata ##
Sign, with the specified key(s), the metadata of the role indicated in --role.
The Snapshot and Timestamp role are also automatically signed, if possible.
```Bash
$ repo.py --sign </path/to/key> ... [--role <rolename>, --path </path/to/repo>]
```

For example, to sign the delegated `foo` metadata:
```Bash
$ repo.py --sign /path/to/foo_key --role foo
```

Note: In the future, the user might have the option of disabling automatic
signing of Snapshot and Timestamp metadata.



## Delegation ##

Delegate trust of target files from the Targets role (or the one specified
in --role) to some other role (--delegatee).  --delegatee is trusted to
sign for target files that match the delegated glob patterns.

```Bash
$ repo.py --delegate <glob pattern> ... --delegatee <rolename> --pubkeys
</path/to/pubkey.pub> ... [--role <rolename> --terminating --threshold <X>
--sign </path/to/role_privkey>]
```

For example, to delegate trust of `foo*.gz` packages to the `foo` role:

```
$ repo.py --delegate "foo*.tgz" --delegatee foo --pubkeys tufkeystore/foo.pub
```



## Revocation ##

Revoke trust of target files from a delegated role (--delegatee).  The
"targets" role performs the revocation if --role is not specified.
```Bash
$ repo.py --revoke --delegatee <rolename> [--role <rolename>
--sign </path/to/role_privkey>]
```



## Verbosity ##

Set the verbosity of the logger (2, by default).  The lower the number, the
greater the verbosity.  Logger messages are saved to `tuf.log` in the current
working directory.
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
