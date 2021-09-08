#  Accept metadata that includes unrecognized fields

- Status: accepted
- Date: 2021-04-08

Technical Story: https://github.com/theupdateframework/python-tuf/issues/1266

## Context and Problem Statement

The current reference implementation will ignore unrecognized fields in a
metadata file when loading it.
This leads to the side effect that if you read a metadata file with unrecognized
fields and immediately write it back to the disk, this file will be modified.

Furthermore, some TAPs like:
- [TAP 6](https://github.com/theupdateframework/taps/blob/master/tap6.md)
- [TAP 10](https://github.com/theupdateframework/taps/blob/master/tap10.md)
- [TAP 14](https://github.com/theupdateframework/taps/blob/master/tap14.md)
- [TAP 15](https://github.com/theupdateframework/taps/blob/master/tap15.md)
- [TAP 16](https://github.com/theupdateframework/taps/blob/master/tap16.md)

are relying on that unrecognized fields will be accepted to introduce new fields
to the specification without making the metadata invalid for older clients who
don't recognize the field.

## Decision Drivers
- The TUF specification implies support for unrecognized attribute-value fields,
see [Document formats](https://theupdateframework.github.io/specification/latest/#document-formats)
- If we perform the following operations on a metadata file with no
intermediate operations:
1. read the metadata file
2. write the metadata file back to the disk

then, the checksum (the content) of the file must not be changed.
- Flexibility to add new fields in the spec without adding breaking changes.
- Don't store unrecognized fields when it is not allowed by the specification.

## Considered Options
- Ignore and drop unrecognized fields.
- Ignore, but store unrecognized fields as an additional attribute.
- Ignore, but store unrecognized fields as an additional attribute
except for a couple of places where it's not allowed by the specification.

## Decision Outcome

Chosen option: "Ignore, but store unrecognized fields as an additional attribute
except for a couple of places where it's not allowed by the specification."
The motivation for this decision is that the TUF specification already implies
that we should accept unrecognized fields for backward compatibility and easier
future extensibility.

Additionally, it seems unacceptable to change a metadata file content just by
reading and writing it back.

There are exceptions however for places in the metadata format when it is not
allowed by specification: keys, roles, meta, hashes, and targets are
actual dictionaries (vs JSON objects that most structures in the format are)
where `unrecognized field` is not a meaningful concept.
