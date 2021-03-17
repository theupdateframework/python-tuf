Instructions for Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Note: Development of TUF occurs on the "develop" branch of this repository.

Contributions can be made by submitting GitHub pull requests.  Submitted code
should follow our `code style guidelines
<https://github.com/secure-systems-lab/code-style-guidelines>`_, which provide
examples of what to do (or not to do) when writing Python code.

Contributors must also indicate acceptance of the `Developer Certificate of
Origin <https://developercertificate.org/>`_  (DCO) when making a contribution
to the project.  Acceptance of the DCO can be established by appending a
``Signed-off-by: Your Name <example@domain.com>`` to the Git commit message.
For example:

::

    Commit message

    Signed-off-by: Vladimir Diaz <vladimir.v.diaz@gmail.com>

The required ``Signed-off-by`` text can be automatically appended to the commit
message via the ``-s`` command-line option to ``git commit``:

::

  $ git commit -s -m "Commit message"

The full text of the DCO:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.

    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I have the
    right to submit it under the open source license indicated in the file; or

    (b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or

    (c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.

    (d) I understand and agree that this project and the contribution are
    public and that a record of the contribution (including all personal
    information I submit with it, including my sign-off) is maintained
    indefinitely and may be redistributed consistent with this project or the
    open source license(s) involved.


To facilitate development and installation of edited version of the code base,
developers are encouraged to install `Virtualenv <https://virtualenv.pypa.io/en/latest/index.html>`_,
which is a tool to create isolated Python environments.  It includes
``pip`` and ``setuptools``, Python packages that can be used to
install TUF and its dependencies. All installation methods of
virtualenv are outlined in the `installation
section <https://virtualenv.pypa.io/en/latest/installation.html>`_,
and instructions for installing locally from source are provided here:
::

    $ curl -O https://pypi.python.org/packages/source/v/virtualenv/virtualenv-15.0.3.tar.gz
    $ tar xvfz virtualenv-15.0.3.tar.gz
    $ cd virtualenv-15.0.3
    $ python virtualenv.py myVE


Development Installation
========================

To work on the TUF project, it's best to perform a development install.

1. First, `install non-Python dependencies <INSTALLATION.rst#non-python-dependencies>`_.

2. Then clone this repository:

::

    $ git clone https://github.com/theupdateframework/tuf

3. Then perform a full, editable/development install.  This will include all
   optional cryptographic support, the testing/linting dependencies, etc.
   With a development installation, modifications to the code in the current
   directory will affect the installed version of TUF.

::

    $ pip install -r requirements-dev.txt


Testing
=======

The Update Framework's unit test suite can be executed by invoking the test
aggregation script inside the *tests* subdirectory. ``tuf`` and its
dependencies must already be installed (see above).
::

    $ cd tests
    $ python aggregate_tests.py

Individual tests can also be executed. Optional '-v' flags can be added to
increase log level up to DEBUG ('-vvvv').
::

    $ python test_updater.py # run a specific test file
    $ python test_updater.py TestUpdater.test_4_refresh # run a specific test
    $ python test_updater.py -vvvv TestUpdater.test_4_refresh # run test with DEBUG log level


All of the log levels and the corresponding options that could be used for testing are:

.. list-table::
   :widths: 20 25
   :header-rows: 1

   * - Option
     - Log Level
   * - default (no argument passed)
     - ERROR (test names are not printed)
   * - `-v`
     - ERROR (test names are printed at this level and above)
   * - `-vv`
     - WARNING
   * - `-vvv`
     - INFO
   * - `-vvvv`
     - DEBUG


To run the tests and measure their code coverage, the aggregation script can be
invoked with the ``coverage`` tool (requires installation of ``coverage``, e.g.
via PyPI).
::

    $ coverage run aggregate_tests.py && coverage report


To develop and test ``tuf`` with above commands alongside its in-house dependency
`securesystemslib <https://github.com/secure-systems-lab/securesystemslib>`_,
it is recommended to first make an editable install of ``tuf`` (in
a *venv*), and then install ``securesystemslib`` in editable mode too (in the same *venv*).
::

    $ cd path/to/tuf
    $ pip install -r requirements-dev.txt
    $ cd path/to/securesystemslib
    $ pip install -r requirements-dev.txt


With `tox <https://testrun.org/tox/>`_ the test suite can be executed in a
separate *venv* for each supported Python version. While the supported
Python versions must already be available, ``tox`` will install ``tuf`` and its
dependencies anew in each environment.
::

    $ tox


An additional non-default ``tox`` environment is available and can be used to
test ``tuf`` against the tip of development of ``securesystemslib`` on GitHub,
to e.g. prepare the former for a new release of the latter.
::

    $ tox -e with-sslib-master
