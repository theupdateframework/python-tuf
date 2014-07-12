## Client Setup ##

The following [repository tool](README.md) function creates a directory
structure that a client downloading new software using TUF (via tuf/client/updater.py) 
expects. The `root.json` metadata file must exist, and also the directories that hold
the metadata files downloaded from a repository.  Software updaters integrating with
TUF may use this directory to store TUF updates saved on the client side.

```python
>>> from tuf.repository_tool import *
>>> create_tuf_client_directory("/path/to/repository/", "/path/to/client/")
```

`create_tuf_client_directory()` moves metadata from `/path/to/repository/metadata`
to `/path/to/client/`.  The repository in `/path/to/repository/` may be the repository
example created in the repository tool [README](README.md).


## Test TUF Locally ##
Run the local TUF repository server.
```Bash
$ cd "/path/to/repository/"; python -m SimpleHTTPServer 8001
```

Retrieve targets from the TUF repository and save them to `/path/to/client/`.  The
`basic_client.py` module is available in `tuf/client/`.
In a different command-line prompt . . .
```Bash
$ cd "/path/to/client/"
$ ls
metadata/

$ basic_client.py --repo http://localhost:8001
$ ls . targets/ targets/django/
.:
metadata  targets  tuf.log

targets/:
django  file1.txt  file2.txt

targets/django/:
file4.txt
```
