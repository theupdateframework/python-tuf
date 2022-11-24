# TUF Client Example


TUF Client Example, using ``python-tuf``.

This TUF Client Example implements the following actions:
   - Client Initialization
   - Target file download

The client can be used against any TUF repository that serves metadata and
targets under the same URL (in _/metadata/_ and _/targets/_ directories, respectively). The
used TUF repository can be set with `--url` (default repository is "http://127.0.0.1:8001"
which is also the default for the repository example).


### Example with the repository example

In one terminal, run the repository example and leave it running:
```console
examples/repository/repo
```

In another terminal, run the client:

```console
# initialize the client with Trust-On-First-Use
./client tofu

# Then download example files from the repository:
./client download file1.txt
```

Note that unlike normal repositories, the example repository only exists in
memory and is re-generated from scratch at every startup: This means your
client needs to run `tofu` everytime you restart the repository application.


### Example with a repository on the internet

```console
# On first use only, initialize the client with Trust-On-First-Use
./client --url https://jku.github.io/tuf-demo tofu

# Then download example files from the repository:
./client --url https://jku.github.io/tuf-demo download demo/succinctly-delegated-1.txt
```
