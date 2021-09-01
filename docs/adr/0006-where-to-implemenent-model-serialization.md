# Separate metadata serialization from metadata class model but keep helpers

Technical Story: https://github.com/theupdateframework/python-tuf/pull/1279

## Context and Problem Statement
In the course of implementing a class-based role metadata model we have also
reviewed options on how to design serialization infrastructure between wire
formats and the class model. In an initial attempt we have implemented
serialization on the metadata class (see option 1), but issues with inheritance
and calls for more flexibility have caused us to rethink this approach.

## Decision Drivers
* A class-based role metadata model (see ADR4) requires serialization routines
  from and to wire formats
* TUF integrators may require custom serialization implementations for custom
  wire formats
* Readability and simplicity of implementation for users and maintainers
* Recognizability of specification

## Considered Options
1. Serialization in metadata classes
2. Serialization in metadata subclasses
3. Serialization separated from metadata classes
4. Compromise 1: Default serialization methods in metadata classes /
   non-default serialization separated
5. Compromise 2: Serialization separated / dict conversion helper methods for
   default serialization in metadata classes

## Decision Outcome
Chosen option: "Compromise 2", because implementing dict conversion as methods
on a corresponding class is idiomatic and allows for well-structured code.
Together with a separated serialization interface, it provides both ease of use
and maintenance, and full flexibility with regards to custom serialization
implementations and wire formats.

## Pros and Cons of the Options

### Option 1: Serialization in metadata classes

Serialization is implemented on metadata classes, e.g.
`Metadata.serialize_as_json()`, etc.

* Good, because serialization for any object is encapsulated within the
  corresponding class and thus structured in small code chunks, using the
  already existing hierarchical class model structure.
* Good, because the TUF specification is heavily based on json, even if only
  for illustrative purposes, thus this option facilitates recognizability.
* Bad, because it might suggest that TUF is limited to json alone.
* Bad, because it does not facilitate custom serialization implementations.
* Bad, because it can get complicated with inheritance in the class model.
  *NOTE: a workaround exists in #1279.*

### Option 2: Serialization in metadata subclasses
Serialization is implemented on metadata subclasses, e.g.
`JsonMetadata.serialize()`, etc.

* Good, because the wire format is decoupled from the base classes, not giving
  the impression that TUF is limited to json, and facilitating custom
  implementations.
* Bad, because a user needs to decide on serialization ahead of time, when
  instantiating the metadata objects.
* Bad, because the metadata model has many classes, which would all need to be
  subclassed accordingly.

### Option 3: Serialization separated from metadata classes
Serialization is implemented independently of the metadata class, e.g. by
defining an abstract `Serializer` interface, which must be implemented in
subclasses, e.g. `JsonSerializer`, etc.

* Good, because the wire format is completely decoupled from the class model,
  not giving the impression that TUF is limited to json, and facilitating
  custom implementations.
* Good, because it can serve as exact blueprint for custom implementations.
* Bad, because a decoupled serialization implementation needs to "re-implement"
  the entire class hierarchy, likely in a procedural manner.

### Option 4: Compromise 1
Default json serialization is implemented on the metadata class as described in
(1), but can be overridden using an independent `Serializer` interface as
described in (3).

* Good, for the reasons outlined in options (1) and (3), i.e. encapsulation
  within classes but decoupled class model and wire format.
* Bad, because it creates two different code paths for default and non-default
  wire formats making the code more complex and prone to deteriorate,
  especially on the non-default path.
* Bad, because the on-the-class default implementation can not be used as
  blueprint for custom implementations.

### Option 5: Compromise 2
Serialization is implemented independently of the metadata class as described
in (3). However, the *meat* of the default `JsonSerializer`, i.e. conversion
between metadata objects and dicts, is implemented on the metadata class, e.g.
as `Metadata.to_dict()`, etc.

* Good, for the reasons outlined in options (1) and (3), i.e. encapsulation
  within classes but decoupled class model and wire format, without the
  disadvantage in (4) of having two completely different code paths.
* Good, because it makes the separate default serializer a minimal wrapper
  around the dict conversion methods.
* Good, because other serialization implementations might also make use of dict
  conversion methods.
* Good, because conversion between class objects and dicts is akin to type
  casting, which is idiomatic to implement on the class.
* Bad, because the on-the-class default implementation can not be used as
  blueprint for custom implementations.

## Links
* [ADR4: Add classes for complex metadata attributes (decision driver)](/Users/lukp/tuf/tuf/docs/adr/0004-extent-of-OOP-in-metadata-model.md)
* [PR: Add simple TUF role metadata model (implements option 1)](https://github.com/theupdateframework/python-tuf/pull/1112)
  - [details about separation of serialization and instantiation](https://github.com/theupdateframework/python-tuf/commit/f63dce6dddb9cfbf8986141340c6fac00a36d46e)
  - [code comment about issues with inheritance](https://github.com/theupdateframework/python-tuf/blob/9401059101b08a18abc5e3be4d60e18670693f62/tuf/api/metadata.py#L297-L306)
* [PR: New metadata API: add MetadataInfo and TargetFile classes (recent ADR discussion impetus)](https://github.com/theupdateframework/python-tuf/pull/1223)
  - [more discussion about issues with inheritance](https://github.com/theupdateframework/python-tuf/pull/1223#issuecomment-737188686)
* [SSLIB/Issue: Add metadata container classes (comparison of options 1 and 2)](https://github.com/secure-systems-lab/securesystemslib/issues/272)
* [tuf-on-a-plane parser (implements option 3)](https://github.com/trishankatdatadog/tuf-on-a-plane/blob/master/src/tuf_on_a_plane/parsers/)
