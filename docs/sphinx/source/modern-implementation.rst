Modern implementation
=====================

The reference implementation is being refactored using  
`modern Python <https://github.com/theupdateframework/tuf/tree/develop/docs/adr/0001-python-version-3-6-plus.md>`_
to both:

* Address scalability and integration issues identified in supporting integration
  into the Python Package Index (PyPI), and other large-scale repositories.
* Ensure maintainability of the project.

This implementation consists of:

* a "low-level" metadata API, designed to provide easy and safe access to
  TUF metadata and handle (de)serialization from/to files, provided in the
  :doc:`tuf.api` module.

* an implementation of the detailed client workflow built on top of the
  metadata API, provided in the :doc:`tuf.ngclient` module.

.. note:: The modern implementation is not considered production ready and
   does not yet provide any high-level support for implementing 
   `repository operations <https://theupdateframework.github.io/specification/latest/#repository-operations>`_, 
   though the addition of API to support them is planned.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   tuf.api
   tuf.ngclient