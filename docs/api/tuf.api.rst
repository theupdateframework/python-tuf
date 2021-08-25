Metadata API
===============

The low-level Metadata API contains two modules:

* :doc:`tuf.api.metadata` contains the actual Metadata abstraction
  that higher level libraries and application code should use to interact
  with TUF metadata. This abstraction provides safe reading and writing to
  supported file formats and helper functions for accessing and modifying
  the metadata contents.
* :doc:`tuf.api.serialization` covers serializing the metadata into
  specific wire formats (like json).

.. toctree::
   :hidden:

   tuf.api.metadata
   tuf.api.serialization
