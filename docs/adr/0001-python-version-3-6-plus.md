# Default to Python 3.6 or newer for new development

* Status: accepted
* Date: 2020-10-20

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1125

## Context and Problem Statement

We are planning a refactor of tuf where:

* We do not want to try and support end-of-life versions of the language.
* We want to use modern language features, such as typing.
* We want to ease maintainer burden, by reducing the major language versions supported.

## Decision Drivers

* Python 2.7 is end-of-life
* Python 3.5 is end-of-life
* Modern Python allows use of desirable features such as type hints
* Supporting end-of-life Python versions adds maintenance overhead

## Considered Options

* Support Python 2.7 and 3.5+
* Support Python 2.7 and 3.6+
* Support Python 2.7 and 3.6+ (with polyfill modules)
* Support only Python 3.6+

## Decision Outcome

Chosen option: "Support only Python 3.6+", because we want modern features and lower
maintainer effort as we work to improve our codebase through the refactor effort.

New modules should target Python 3.6+.

Using modules to polyfill standard library features from Python 3.6+ feels
untenable as more libraries are dropping support for EOL Python releases.

### Negative Consequences

* Leaves major adopter and contributor without an actively developed client for some of
  their customers stuck on older Python versions.

## Links

* [Discussion of how/where to develop the refactored codebase](https://github.com/theupdateframework/python-tuf/issues/1126)
* [Discussion of deprecation policy for the pre-1.0, Python 2.7 supporting, code](https://github.com/theupdateframework/python-tuf/issues/1127)
