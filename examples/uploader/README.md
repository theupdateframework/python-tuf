# TUF Uploader Tool Example

:warning: This example uses the repository module which is not considered
part of the python-tuf stable API quite yet.

This is an example maintainer tool: It makes it possible to add delegations to
a remote repository, and then to upload delegated metadata to the repository.

Features:
   - Initialization (much like the [client example](../client/))
   - Claim delegation: this uses "unsafe repository API" in the sense that the
     uploader sends repository unsigned data. This operation can be
     compared to claiming a project name on PyPI.org
   - Add targetfile: Here uploader uses signing keys that were added to the
     delegation in the previous step to create a new version of the delegated
     metadata. The repository will verify signatures on this metadata.

The used TUF repository can be set with `--url` (default repository is
"http://127.0.0.1:8001" which is also the default for the repository example).
In practice the uploader tool is only useful with the repository example.

### Usage with the repository example

In one terminal, run the [repository example](../repository/) and leave it running:
```console
examples/repository/repo
```

In another terminal, run uploader:

```console
# Initialize with Trust-On-First-Use
./uploader tofu

# Then claim a delegation for yourself (this also creates a new signing key):
./uploader add-delegation myrole

# Then add a new downloadable target file to your delegated role (to keep the
# example simple, the target file content is always the targetpath):
./uploader add-target myrole myrole/mytargetfile
```

At this point "myrole/mytargetfile" is downloadable from the repository
with the [client example](../client/).
