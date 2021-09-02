# Develop TUF 1.0.0 in a subdirectory of the current TUF implementation

* Status: accepted
* Date: 2020-11-23

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1126

## Context and Problem Statement

The plan is to implement a refactored TUF (1.0.0) alongside the current
code base, in order to not disrupt existing usage and keep providing
a Python 2.7 client.

We need to decide on the best place to do this development.

## Decision Drivers

* Developing the new code piecemeal
* Continuing to make releases in the interim
* Avoiding maintenance overhead

## Considered Options

Develop TUF 1.0.0:

* In its own repository
* In a separate development branch of the current TUF implementation
* In the default branch, archiving the current implementation
* In a subdirectory of the current TUF implementation

## Decision Outcome

Chosen option: "Develop TUF 1.0.0 in a subdirectory of the current TUF
implementation", because we want to add the new TUF code gradually
while keep maintaining the current implementation given limited
maintenance resources.

Once development of the new version is complete, we will transition
from TUF 1.0.0 in a subdirectory to stand-alone TUF 1.0.0 by the following
procedure:

* flesh out tuf/api/*
* implement tuf/client/new-updater.py
* implement tuf/repository/*
* \<iterate\>
* git mv tuf/client/new-updater.py tuf/client/updater.py
* git rm tuf/\*.py
* tag 1.0.0

## Pros and Cons of the Options

Developing TUF 1.0.0 in a subdirectory of the current TUF
implementation seems to have the least maintenance overhead compared to
option 1 and 2, while allowing us to continue making releases with the
old code unlike option 3.

### Negative Consequences

* In progress development in the default branch causes messiness
  in plain sight.

## Links

* [Discussion of Python version support in TUF 1.0.0](https://github.com/theupdateframework/python-tuf/issues/1125)
* [Discussion of deprecation policy for the pre-1.0, Python 2.7 supporting, code](https://github.com/theupdateframework/python-tuf/issues/1127)
