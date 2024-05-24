QuickStart Guide
=================

The guide will walk through the basic steps to set up and use TUF in your Python projects using the python-tuf library.

Prerequisites
-------------

- Python 3.6 or newer installed
- pip (Python package installer) installed

Installation
------------

Check the `Installation guide <./INSTALLATION.rst>`_ for installing TUF.

Step 1: Initialize a Repository
-------------------------------

Create a new directory for your repository and initialize it. This creates the necessary directory structure and configuration files for a TUF repository:

.. code-block:: bash

   mkdir my_tuf_repo
   cd my_tuf_repo
   tuf init-repo.

Step 2: Generate Keys
---------------------

Generate keys for the root, targets, snapshot, and timestamp roles. These keys are used to sign the TUF metadata files, ensuring the integrity and authenticity of the repository:

.. code-block:: bash

   tuf generate-key root
   tuf generate-key targets
   tuf generate-key snapshot
   tuf generate-key timestamp

Keep these keys secure, especially the root key. They form the basis of trust for your repository.

Step 3: Add a Target File
-------------------------

Create a sample target file and include it in the repository. This file represents the actual content that you want to distribute securely:

.. code-block:: bash

   echo "Hello, World!" > hello_world.txt
   tuf add-target./hello_world.txt

Step 4: Sign the Repository
---------------------------

Sign the metadata files of the repository using the generated keys, which ensures authenticity and integrity of the metadata:

.. code-block:: bash

   tuf sign

Step 5: Serve the Repository
----------------------------

Now, make the repository available to clients by serving the metadata and target files with a web server. For example, with Python's built-in HTTP server:

.. code-block:: bash

   python -m http.server 8000

Step 6: Set Up the Client
-------------------------

Now, to use the TUF client, set up a Python script that creates an instance of the `Updater` class, pointing to your repository's metadata and target files:

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

Run your client script to download the target file securely:

.. code-block:: bash

   python client_script.py

The client script will download the target file (`hello_world.txt`) after verifying the repository's metadata.

Updating the Target File
------------------------

To update the target file on the repository side:

1. Modify the `hello_world.txt` file with new content.
2. Then run `tuf add-target./hello_world.txt` to update the targets metadata.
3. Run `tuf sign` to sign the updated metadata.
4. Serve updated repository files.

On the client side, run the client script once again:

.. code-block:: bash

   python client_script.py

The client will notice the updated metadata and download the new version of the target file.

Best Practices
--------------

- Keep your keys safe, and secure them against unauthorized access. Use HSMs (hardware security modules) for key storage.
- Rotate your keys regularly to limit key compromise.
- Use different keys for each role to keep the trust given to single keys low.
- Monitor your repository regularly for tampering and other unauthorized changes.

For more advanced features and details, see the `python-tuf documentation <https://python-tuf.readthedocs.io/>`_.
