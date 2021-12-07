# TUF Client Example


TUF Client Example, using ``python-tuf``.

This TUF Client Example implements the following actions:
   - Client Infrastructure Initialization
   - Download target files from TUF Repository

The example client expects to find a TUF repository running on localhost. We
can use the static metadata files in ``tests/repository_data/repository``
to set one up.

Run the repository using the Python3 built-in HTTP module, and keep this
session running.

```console
   $ python3 -m http.server -d tests/repository_data/repository
   Serving HTTP on :: port 8000 (http://[::]:8000/) ...
```

How to use the TUF Client Example to download a target file.

```console
$ ./client_example.py download file1.txt
```
