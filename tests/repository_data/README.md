# Unit and integration testing

## Running the tests
The unit and integration tests can be executed by invoking `tox` from any
path under the project directory.

```
$ tox
```

Or by invoking `aggregate_tests.py` from the
[tests](https://github.com/theupdateframework/python-tuf/tree/develop/tests)
directory.

```
$ python3 aggregate_tests.py
```

Note: integration tests end in `_integration.py`.

If you wish to run a particular unit test, navigate to the tests directory and
run that specific unit test.  For example:

```
$ python3 test_updater.py
```

It it also possible to run the test cases of a unit test.  For instance:

```
$ python3 -m unittest test_updater.TestMultiRepoUpdater.test_get_one_valid_targetinfo
```

## Setup
The unit and integration tests operate on static metadata available in the
[repository_data
directory](https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data/).
Before running the tests, static metadata is first copied to temporary
directories and modified, as needed, by the tests.

The test modules typically spawn HTTP(S) servers that serve metadata and target
files for the unit tests.  The [map
file](https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data)
specifies the location of the test repositories and other properties.  For
specific targets and metadata provided by the tests repositories, please
inspect their [respective
metadata](https://github.com/theupdateframework/python-tuf/tree/develop/tests/repository_data/repository).

