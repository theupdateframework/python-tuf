# Python Client Example

Introduction
============

Python Client Example, using ``python-tuf``.

This Python Client Example implements the following actions:
   - Client Infrastructure Initialization
   - Download target files from TUF Repository


Repository
==========

This example demonstrates how to use the ``python-tuf`` to build a client
application.

The repository will use static files.
The static files are available in the ``python-tuf`` source code repository in
``tests/repository_data/repository``.

Run the repository using the Python3 built-in HTTP module, and keep this
session running.

```console
   $ python3 -m http.server -d tests/repository_data/repository
   Serving HTTP on :: port 8000 (http://[::]:8000/) ...
```

Client Example
==============

The [Client Example source code](./client_example.py>) is available entirely
in this source code repository.

How to use the Client Example:


1. Download the ``file1.txt``

   ```console
   $ ./client_example.py download file1.txt
   Download directory [./downloads] was created
   Metadata folder [<metadata dir>] was created
   Added trusted root in /Users/kdearaujo/.local/share/python-tuf-client-example
   Found trusted root in <metadata dir>
   Target downloaded and available in ./downloads/file1.txt
   ```

2. Download again ``file1.txt``

   ```console
   $ ./client_example.py download file1.txt
   Found trusted root in <metadata dir>
   Target is available in ./downloads/file1.txt
   ```
