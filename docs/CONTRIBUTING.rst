Instructions for contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Contribute to python-tuf by submitting pull requests against the "develop"
branch of this repository. Detailed instructions are available in our
`development guidelines
<https://github.com/secure-systems-lab/lab-guidelines/blob/master/dev-workflow.md>`_.
All submitted code should follow our `style guidelines
<https://github.com/secure-systems-lab/code-style-guidelines/blob/master/python.md>`_
and must be `unit tested <#unit-tests>`_.

.. note::

     Also see `development installation instructions <https://theupdateframework.readthedocs.io/en/latest/INSTALLATION.html#install-for-development>`_.

DCO
===

Contributors must indicate acceptance of the `Developer Certificate of
Origin <https://developercertificate.org/>`_ by appending a ``Signed-off-by:
Your Name <example@domain.com>`` to each git commit message (see `git commit
--signoff <https://git-scm.com/docs/git-commit#Documentation/git-commit.txt---signoff>`_).

Testing
=======

With `tox <https:///tox.wiki>`_ the whole test suite can be executed in
a separate *virtual environment* for each supported Python version available on
the system. ``tuf`` and its dependencies are installed automatically for each
tox run.

::

     tox

Below, you will see more details about each step managed by ``tox``, in case
you need debug/run outside ``tox``.

Unit tests
----------

More specifically, the Update Framework's test suite can be executed by invoking
the test aggregation script inside the *tests* subdirectory. ``tuf`` and its
dependencies must already be installed.
::

     cd tests/
     python3 aggregate_tests.py


Individual tests can also be executed. Optional ``-v`` flags can be added to
increase log level up to DEBUG (``-vvvv``).
::

     cd tests/
     python3 test_updater_ng.py -v


Coverage
--------

To run the tests and measure their code coverage, the aggregation script can be
invoked with the ``coverage`` tool (requires installation of ``coverage``, e.g.
via PyPI).
::

     cd tests/
     coverage run aggregate_tests.py && coverage report


Auto-formatting
---------------

The linter in CI/CD will check that new TUF code is formatted with
`ruff <https://docs.astral.sh/ruff/>`_. Auto-formatting can be done on the
command line:
::

     tox -e fix
