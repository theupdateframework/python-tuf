# Python Client Example

Introduction
============

Python Client Example, using ``python-tuf``.

For information about installing ``python-tuf``, please refer to the
[Installation documentation](https://theupdateframework.readthedocs.io/en/latest/INSTALLATION.html).


Preparing
=========

To have the example working in your machine, clone the ``python-tuf`` in your
system.

```console
$ git clone git@github.com:theupdateframework/python-tuf.git
```


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

1. Initialize the Client

   ```console
   $ ./client_example.py --init
   ```

   This action is to create the client infrastructure properly.

   This infrastructure consists in:
    - Metadata repository
    - Download folder for targets
    - Bootstrap 1.root.json


2. Download the ``file1.txt``

   ```console
   $ ./client_example.py download file1.txt
   Top-level metadata is refreshed.
   Target info gotten.
   File downloaded available in ./downloads/file2.txt.
   ```

3. Download a not available ``file_na.txt``

   ```console
   $ ./client_example.py download file_na.txt
   Top-level metadata is refreshed.
   Target info gotten.
   Target file not found.
   ```

4. Download again ``file1.txt``

   ```console
   $ ./client_example.py download file1.txt
   Top-level metadata is refreshed.
   Target info gotten.
   File is already available in ./downloads/file1.txt.
   ```
