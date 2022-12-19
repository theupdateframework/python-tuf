# TUF Repository Application Example

:warning: This example uses the repository module which is not considered
part of the python-tuf stable API quite yet.

This TUF Repository Application Example has the following features:
- Initializes a completely new repository on startup
- Stores everything (metadata, targets, signing keys) in-memory
- Serves metadata and targets on localhost (default port 8001)
- Simulates a live repository by automatically adding a new target
  file every 10 seconds.


### Usage

```console
./repo
```
Your repository is now running and is accessible on localhost, See e.g.
http://127.0.0.1:8001/metadata/1.root.json. The
[client example](../client_example/README.md) uses this address by default.
