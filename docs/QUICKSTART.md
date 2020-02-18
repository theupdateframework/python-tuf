# Quickstart #

In this quickstart tutorial, we'll use the basic TUF command-line interface
(CLI), which includes the `repo.py` script and the `client.py` script, to set
up a repository with an update and metadata about that update, then download
and verify that update as a client.

Unlike the underlying TUF modules that the CLI uses, the CLI itself is a bit
bare-bones.  Using the CLI is the easiest way to familiarize yourself with
how TUF works, however.  It will serve as a very basic update system.

----

**Step (0)** - Make sure TUF is installed.

Make sure that TUF is installed, along with some of the optional cryptographic
libraries and C extensions.  Try this command to do that:
`pip install securesystemslib[colors,crypto,pynacl] tuf`

If you run into errors during that pip command, please consult the more
detailed [TUF Installation Instructions](INSTALLATION.rst).  (There are some
system libraries that you may need to install first.)


**Step (1)** - Create a basic repository and client.

The following command will set up a basic update repository and basic client
that knows about the repository.  `tufrepo`, `tufkeystore`, and
`tufclient` directories will be created in the current directory.

```Bash
$ repo.py --init
```

Four sets of keys are created in the `tufkeystore` directory.  Initial metadata
about the repository is created in the `tufrepo` directory, and also provided
to the client in the `tufclient` directory.


**Step (2)** - Add an update to the repository.

We'll create a target file that will later be delivered as an update to clients.
Metadata about that file will be created and signed, and added to the
repository's metadata.

```Bash
$ echo 'Test file' > testfile
$ repo.py --add testfile
$ tree tufrepo/
tufrepo/
├── metadata
│   ├── 1.root.json
│   ├── root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
├── metadata.staged
│   ├── 1.root.json
│   ├── root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
└── targets
    └── testfile

    3 directories, 11 files
```

The new file `testfile` is added to the repository, and metadata is updated in
the `tufrepo` directory.  The Targets metadata (`targets.json`) now includes
the file size and hashes of the `testfile` target file, and this metadata is
signed by the Targets role's key, so that clients can verify that metadata
about `testfile` and then verify `testfile` itself.


**Step (3)** - Serve the repo.

We'll host a toy http server containing the `testfile` update and the
repository's metadata.

```Bash
$ cd "tufrepo/"
$ python3 -m http.server 8001

# or, if you are using Python2:
$ python -m SimpleHTTPServer 8001

```

**Step (4)** - Obtain and verify the `testfile` update on a client.

The client can request the package `testfile` from the repository.  TUF will
download and verify metadata from the repository as necessary to determine
what the trustworthy hashes and length of `testfile` are, then download
the target `testfile` from the repository and keep it only if it matches that
trustworthy metadata.

```Bash
$ cd "../tufclient/"
$ client.py --repo http://localhost:8001 testfile
$ tree
.
├── tufrepo
│   └── metadata
│       ├── current
│       │   ├── 1.root.json
│       │   ├── root.json
│       │   ├── snapshot.json
│       │   ├── targets.json
│       │   └── timestamp.json
│       └── previous
│           ├── 1.root.json
│           ├── root.json
│           ├── snapshot.json
│           ├── targets.json
│           └── timestamp.json
└── tuftargets
    └── testfile

    5 directories, 11 files
```

Now that a trustworthy update target has been obtained, an updater can proceed
however it normally would to install or use the update.

----

### Next Steps

TUF provides functionality for both ends of a software update system, the
**update provider** and the **update client**.

`repo.py` made use of `tuf.repository_tool`'s functionality for an update
provider, helping you produce and sign metadata about your updates.

`client.py` made use of `tuf.client.updater`'s client-side functionality,
performing download and the critical verification steps for metadata and the
update itself.

You can look at [CLI.md](CLI.md) to toy with the TUF CLI a bit more.
After that, try out using the underlying modules for a great deal more control.
The more detailed [Advanced Tutorial](TUTORIAL.md) shows you how to use the
underlying modules, `repository_tool` and `updater`.

Ultimately, a sophisticated update client will use or re-implement those
underlying modules.  The TUF design is intended to play well with any update
workflow.

Please provide feedback or questions for this or other tutorials, or
TUF in general, by checking out
[our contact info](https://github.com/theupdateframework/tuf#contact), or
creating [issues](https://github.com/theupdateframework/tuf/issues) in this
repository!
