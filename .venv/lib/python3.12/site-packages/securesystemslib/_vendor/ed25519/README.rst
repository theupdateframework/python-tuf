ed25519
=======

.. image:: https://github.com/pyca/ed25519/workflows/CI/badge.svg
   :target: https://github.com/pyca/ed25519/actions?query=workflow%3ACI

`Ed25519 <http://ed25519.cr.yp.to/>`_ is a high-speed public-key
signature system.  ``ed25519.py`` is based on the original Python
implementation published on the Ed25519 website, with major
optimizations to make it run reasonably fast.


Warning
-------

This code is **not safe** for use with secret data.  Even operating on
public data (i.e., verifying public signatures on public messages), it
is slower than alternatives.

The issue is that our computations may behave differently depending on
their inputs in ways that could reveal those inputs to an attacker;
they may take different amounts of time, and may have different memory
access patterns.  These side-channel attacks are difficult to avoid in
Python, except perhaps with major sacrifice of efficiency.

This code may be useful in cases where you absolutely cannot have any
C code dependencies.  Otherwise, `PyNaCl
<https://github.com/pyca/pynacl>`_ provides a version of the original
author's C implementation, which runs faster and is carefully
engineered to avoid side-channel attacks.


Running the tests
-----------------

``ed25519.py`` uses tox to run the test suite. You can run all the tests by using:

.. code:: bash

    $ tox


Resources
---------

* `IRC <http://webchat.freenode.net?channels=%23cryptography-dev>`_
  (#cryptography-dev - irc.freenode.net)
