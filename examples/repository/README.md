# TUF Repository Application Example


This TUF Repository Application Example has following features:
- Initializes a completely new repository on startup
- Stores everything (metadata, targets, signing keys) in-memory
- Serves metadata and targets on localhost (default port 8001)
- Simulates a live repository by automatically adding a new target
  file every 10 seconds.


### Example with the repository example

```console
./repo
```
Your repository is now running and is accessible on localhost, See e.g.
http://127.0.0.1:8001/metadata/1.root.json

Note that because the example generates a new repository at startup,
clients need to also re-initialize their trust root when the repository
application is restarted. With the example client this is done with
`./client tofu`.
