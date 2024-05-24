QuickStart Guide
=================

This guide will walk you through the basic steps to set up and use TUF (The Update Framework) in your Python projects using the python-tuf library.

Prerequisites
-------------

- Python 3.6 or newer installed
- pip (Python package installer) installed

Installation
------------

Check the `Installation guide <./INSTALLATION.rst>`_ for installing TUF.

Step 1: Initialize a Repository
-------------------------------

Create a new directory for your repository and initialize it. This step creates the necessary directory structure and configuration files for a TUF repository:

.. code-block:: bash

   mkdir my_tuf_repo
   cd my_tuf_repo
   tuf init-repo.

Step 2: Generate Keys
---------------------

Generate keys for the root, targets, snapshot, and timestamp roles. These keys are used to sign the TUF metadata files that ensure the integrity and authenticity of the repository:

.. code-block:: bash

   tuf generate-key root
   tuf generate-key targets
   tuf generate-key snapshot
   tuf generate-key timestamp

Keep these keys secure, especially the root key, as they form the trust basis for your repository.

Step 3: Add a Target File
-------------------------

Create a sample target file and add it to the repository. This file represents the actual content you want to distribute securely:

.. code-block:: bash

   echo "Hello, World!" > hello_world.txt
   tuf add-target./hello_world.txt

Step 4: Sign the Repository
---------------------------

Sign the repository's metadata files using the generated keys. This step ensures the authenticity and integrity of the metadata:

.. code-block:: bash

   tuf sign

Step 5: Serve the Repository
----------------------------

To make the repository accessible to clients, serve the metadata and target files via a web server. For example, using Python's built-in HTTP server:

.. code-block:: bash

   python -m http.server 8000

Step 6: Set Up the Client
-------------------------

To use the TUF client, set up a Python script that initializes the `Updater` class, pointing it to your repository's metadata and target files:

.. code-block:: python

   from tuf.ngclient import Updater

   METADATA_BASE_URL = "http://localhost:8000/metadata/"
   TARGET_BASE_URL = "http://localhost:8000/targets/"

   updater = Updater(metadata_base_url=METADATA_BASE_URL, target_base_url=TARGET_BASE_URL)

   updater.refresh()

   target_info = updater.get_targetinfo('hello_world.txt')

   if not updater.find_cached_target(target_info):
       updater.download_target(target_info)

Step 7: Run the Client Script
-----------------------------

Execute your client script to download the target file securely:

.. code-block:: bash

   python client_script.py

The client script will download the target file (`hello_world.txt`) after verifying the repository's metadata.

Updating the Target File
------------------------

To update the target file on the repository side:

1. Modify the `hello_world.txt` file with new content.
2. Run `tuf add-target./hello_world.txt` to update the targets metadata.
3. Run `tuf sign` to sign the updated metadata.
4. Serve the updated repository files.

On the client side, run the client script again:

.. code-block:: bash

   python client_script.py

The client will detect the updated metadata and download the new version of the target file.

Best Practices
--------------

- Keep your keys secure and protect them from unauthorized access. Consider using hardware security modules (HSMs) for key storage.
- Regularly rotate your keys to limit the impact of key compromises.
- Use separate keys for each role to minimize the trust placed in individual keys.
- Continuously monitor your repository for signs of tampering or unauthorized changes.

Conclusion
----------

This QuickStart guide provides a foundational overview of using TUF in Python. It covers the essentials of setting up a repository, managing keys, serving files, and using the client for secure downloads and updates. By following these steps and best practices, you can leverage TUF to secure your software update process.

For more advanced features and detailed information, refer to the [python-tuf documentation](https://python-tuf.readthedocs.io/).
