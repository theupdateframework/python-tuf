# updater.py
**updater.py** is intended as the only TUF module that software update
systems need to utilize for a low-level integration.  It provides a single
class representing an updater that includes methods to download, install, and
verify metadata or target files in a secure manner.  Importing
**tuf.client.updater** and instantiating its main class is all that is
required by the client prior to a TUF update request.  The importation and
instantiation steps allow TUF to load all of the required metadata files
and set the repository mirror information.
