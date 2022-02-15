API Reference
=====================


TUF provides multiple APIs:


* The low-level :doc:`tuf.api` provides access to a Metadata file abstraction
  that closely follows the TUF specification's `document formats`_.
  This API handles de/serialization to and from files and makes it easier to access
  and modify metadata content safely. It is purely focused on individual
  pieces of Metadata and provides no concepts like "repository" or "update
  workflow".

* The `client update workflow`_ is implemented in the :doc:`tuf.ngclient` module:
  It is a higher-level API that provides ways to query and download target files
  securely, while handling the TUF update workflow behind the scenes. ngclient
  is implemented on top of the Metadata API and can be used to implement
  various TUF clients with relatively little effort.

Code `examples <https://github.com/theupdateframework/python-tuf/tree/develop/examples>`_
are available for client implementation using ngclient and a
basic repository using Metadata API.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   tuf.api
   tuf.ngclient

.. _client update workflow: https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
.. _document formats: https://theupdateframework.github.io/specification/latest/#document-formats
