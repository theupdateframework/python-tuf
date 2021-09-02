# Add classes for complex metadata attributes

* Status: accepted
* Date: 2020-11-30

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1133

## Context and Problem Statement
Custom classes for the TUF signed metadata wrapper (Metadata) and metadata
payload containers (Root, Timestamp, Snapshot, Targets) were added recently.
Complex attributes on these classes are still represented as dictionaries.
Should we add classes for these attributes too?

## Decision Drivers

* Transition to class-based role metadata containers in progress (see *"class
  model"* links below)
* Harden in-memory representation of metadata model
* Replace `securesystemslib` schema validation (see *"schema checker"* link
  below)

## Considered Options

* Use custom classes for complex attributes
* Use dictionaries for complex attributes

## Decision Outcome

Chosen option: "Use custom classes for complex attributes", to provide a
consistently object-oriented, well-defined, single source of truth about the
TUF metadata model (not only its containers). In addition to convenience update
methods, the model may be extended with self-validation behavior (see
*"validation guidelines"* link below) to replace `securesystemslib` schema
checks.

### Negative Consequences

* Implementation overhead
* Less flexibility in usage and development (this is actually desired)
* Maybe less idiomatic than dictionaries

## Links

* [class model](https://github.com/theupdateframework/python-tuf/pull/1112)
* [class model (root)](https://github.com/theupdateframework/python-tuf/pull/1193)
* [WIP: class model (complex attributes)](https://github.com/theupdateframework/python-tuf/pull/1223)
* [new TUF validation guidelines](https://github.com/theupdateframework/python-tuf/issues/1130)
* [securesystemslib schema checker issues](https://github.com/secure-systems-lab/securesystemslib/issues/183)
