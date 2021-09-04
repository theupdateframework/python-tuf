# Primary purpose of the reference implementation

* Status: accepted
* Date: 2021-08-25

## Context and Problem Statement

The original goal for the reference implementation refactor was to provide an
implementation which is both an aid to understanding the specification and a
good architecture for other implementations to mimic.

During refactoring efforts on the metadata API and ngclient, several friction
points have arisen where a safe object-oriented API would result in a less
direct mapping to the [Document formats] in the specification.

The archetypal example friction point is that [Timestamp] lists snapshot _only_
in a `meta` dictionary of `METAPATH` -> attribute fields. The dictionary will
only ever contain one value and creates an extra level of indirection for
implementations which try to map to the file format.

When presented with such cases, we have considered multiple options:
* Strict mapping to the [Document formats]
* Simple and safe API in preference to mapping to the [Document formats]
* Strict mapping to the [Document formats] with additional convenience API
  which is documented as the preferred interface for users

So far implementation has tended towards the final option, but this is
unsatisfying because:
* the API contains traps for the unsuspecting users
* two code paths to achieve the same goal is likely to result in inconsistent
  behaviour and bugs

Therefore, we would like to define our primary purpose so that we can make
consistent decisions.

[Document formats]: https://theupdateframework.github.io/specification/latest/#document-formats
[Timestamp]: https://theupdateframework.github.io/specification/latest/#file-formats-timestamp

## Decision Drivers

* The reference implementation is often the starting point for new
  implementations, porting architecture of the reference implementation to new
  languages/frameworks
* Reading reference implementation code is a common way to learn about TUF
* The TUF formats include non-intuitive JSON object formats when mapping to OOP
  objects
* Multiple code paths/API for the same feature is a common source of bugs

## Considered Options

Primary purpose of the reference implementation is:
* a learning resource to aid understanding of the specification (pedagogical reference)
* a good architecture for other implementations to mimic (exemplary reference)

## Decision Outcome

Primary purpose of the reference implementation is as an exemplary reference:
providing a safe, consistent API for users and a good architecture for other
implementations to mimic.

## Links

* Discussed [on Slack](https://cloud-native.slack.com/archives/C01GT17AC5D/p1629357567021600)
* Discussed in the [August 2021 TUF community meeting](https://hackmd.io/jdAk9rmPSpOYUdstbIvbjw#August-25-2021-Meeting)
