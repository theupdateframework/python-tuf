# Repository library design built on top of Metadata API


## Context and Problem Statement

The Metadata API provides a modern Python API for accessing individual pieces
of metadata. It does not provide any wider context help to someone looking to
implement a TUF repository.

The legacy python-tuf implementation offers tools for this but suffers from
some issues (as do many other implementations):
* There is a _very_ large amount of code to maintain: repo.py,
  repository_tool.py and repository_lib.py alone are almost 7000 lines of code.
* The "library like" parts of the implementation do not form a good coherent
  API: methods routinely have a large number of arguments, code still depends
  on globals in a major way and application (repo.py) still implements a lot of
  "repository code" itself
* The "library like" parts of the implementation make decisions that look like
  application decisions. As an example, repository_tool loads _every_ metadata
  file in the repository: this is fine for CLI that operates on a small
  repository but is unlikely to be a good choice for a large scale server.


## Decision Drivers

* There is a consensus on removing the legacy code from python-tuf due to
  maintainability issues
* Metadata API makes modifying metadata far easier than legacy code base: this
  makes significantly different designs possible
* Not providing a "repository library" (and leaving implementers on their own)
  may be a short term solution because of the previous point, but to make
  adoption easier and to help adopters create safe implementations the project
  would benefit from some shared repository code and a shared repository design 
* Maintainability of new library code must be a top concern
* Allowing a wide range of repository implementations (from CLI tools to
  minimal in-memory implementations to large scale application servers)
  would be good: unfortunately these can have wildly differing requirements


## Considered Options

1. No repository packages
2. repository_tool -like API
3. Minimal repository abstraction


## Decision Outcome

Option 3: Minimal repository abstraction

While option 1 might be used temporarily, the goal should be to implement a
minimal repository abstraction as soon as possible: this should give the
project a path forward where the maintenance burden is reasonable and results
should be usable very soon. The python-tuf repository functionality can be
later extended as ideas are experimented with in upstream projects and in
python-tuf example code.

The concept is still unproven but validating the design should be straight
forward: decision could be re-evaluated in a few months if not in weeks.


## Pros and Cons of the Options

### No repository packages

Metadata API makes editing the repository content vastly simpler. There are
already repository implementations built with it[^1] so clearly a repository
library is not an absolute requirement.

Not providing repository packages in python-tuf does mean that external
projects could experiment and create implementations without adding to the
maintenance burden of python-tuf. This would be the easiest way to iterate many
different designs and hopefully find good ones in the end.

That said, there are some tricky parts of repository maintenance (e.g.
initialization, snapshot update, hashed bin management) that would benefit from
having a canonical implementation, both for easier adoption of python-tuf and
as a reference for other implementations. Likewise, a well designed library
could make some repeated actions (e.g. version bumps, expiry updates, signing)
much easier to manage.

### repository_tool -like API

It won't be possible to support the repository_tool API as it is but a similar
one would certainly be an option.

This would likely be the easiest upgrade path for any repository_tool users out
there. The implementation would not be a huge amount of work as Metadata API
makes many things easier.

However, repository_tool (and parts of repo.py) are not a great API. It is
likely that a similar API suffers from some of the same issues: it might end up
being a substantial amount of code that is only a good fit for one application.

### Minimal repository abstraction

python-tuf could define a tiny repository API that
* provides carefully selected core functionality (like core snapshot update)
* does not implement all repository actions itself, instead it makes it easy
  for the application code to do them
* leaves application details to specific implementations (examples of decisions
  a library should not always decide: "are targets stored with the repo?",
  "which versions of metadata are stored?", "when to load metadata?", "when to
  unload metadata?", "when to bump metadata version?", "what is the new expiry
  date?", "which targets versions should be part of new snapshot?")

python-tuf could also provide one or more implementations of this abstraction
as examples -- this could include a _repo.py_- or _repository_tool_-like
implementation.

This could be a compromise that allows:
* low maintenance burden on python-tuf: initial library could be tiny
* sharing the important, canonical parts of a TUF repository implementation
* ergonomic repository modification, meaning most actions do not have to be in
  the core code
* very different repository implementations using the same core code and the
  same abstract API

The approach does have some downsides:
* it's not a drop in replacement for repository_tool or repo.py
* A prototype has been implemented (see Links below) but the concept is still
  unproven

More details in [Design document](../repository-library-design.md).

## Links
* [Design document for minimal repository abstraction](../repository-library-design.md)
* [Prototype implementation of minimal repository abstraction](https://github.com/vmware-labs/repository-editor-for-tuf/)


[^1]:
    [RepositorySimulator](https://github.com/theupdateframework/python-tuf/blob/develop/tests/repository_simulator.py)
    in python-tuf tests is an in-memory implementation, while
    [repository-editor-for-tuf](https://github.com/vmware-labs/repository-editor-for-tuf)
    is an external Command line repository maintenance tool.

