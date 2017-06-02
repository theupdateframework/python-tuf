---
title: The Update Framework
abbrev: TUF
docname: draft-the-update-framework
date: 2017-06-02
category: info

ipr: trust200902
area: TODO
workgroup: TODO
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  - ins: J. Cappos
    name: Justin Cappos
    # TODO

  - ins: V. Diaz
    name: Vladimir V. Diaz
    # TODO

  - ins: E. Hartsuyker
    name: Eric Hartsuyker
    organization: Advanced Telematic Systems GmbH
    email: eric.hartsuyker@advancedtelematic.com
    street: Kantstraße 162
    country: Germany
    region: Berlin
    city: Berlin
    code: 10623

  - ins: T. Karthik
    name: Trishank Karthik
    # TODO

normative:
  RFC2119:
  RFC2616:
  RFC3447:
  RFC4634:
  RFC4648:
  RFC5756:
  RFC7159:

informative:
  RFC1321:
  ED25519:
    title: '"High-Speed High-Security Signatures", Journal of Cryptographic Engineering, Vol. 2'
    author:
      - ins: D. J. Bernstein
      - ins: N. Duif
      - ins: T. Lange
      - ins: P. Schwabe
      - ins: B-Y. Yang
    date: 2011-09-26
  CJSON:
    title: http://wiki.laptop.org/go/Canonical_JSON
    author:
      - ins: One Laptop Per Child
    date: 2015-02-27
  MERCURY:
    # TODO
    title: https://ssl.engineering.nyu.edu/papers/kuppusamy_usenix_17.pdf
    author:
      - ins: Kuppusamy
    date: 2017-01-01

--- abstract

This document describes a framework for securing software update systems.
This framework is itself called The Update Framework and is abbreviated as TUF for convenience.

--- middle

# Introduction

Software is commonly updated through software update systems.
These systems can be package managers that are responsible for all of the software that is installed on a system, application updaters that are only responsible for individual installed applications, or software library managers that install software that adds functionality such as plugins or programming language libraries.

Software update systems all have the common behavior of downloading files that identify whether updates exist and, when updates do exist, downloading the files that are required for the update.
For the implementations concerned with security, integrity and authenticity checks are performed on downloaded files.

Software update systems are vulnerable to a variety of known attacks.
This is generally true even for implementations that have tried to be secure.

## Out of Scope

TUF is not a universal update system, but rather a simple and flexible way that applications can have high levels of security with their software update systems.
Creating a universal software update system would not be a reasonable goal due to the diversity of application-specific functionality in software update systems and the limited usefulness that such a system would have for securing legacy software update systems.

TUF does not define package formats and does not perform the actual update of application files.
TUF provides the simplest mechanism possible that remains easy to use and provides a secure way for applications to obtain and verify files being distributed by trusted parties.

TUF does not provide a means to bootstrap security so that arbitrary installation of new software is secure.
In practice this means that people still need to use other means to verify the integrity and authenticity of files they download manually.

TUF will not have the responsibility of deciding on the correct course of action in all error situations, such as those that can occur when certain attacks are being performed.
Instead, TUF will provide the software update system the relevant information about any errors that require security decisions which are situation-specific.
How those errors are handled is up to the software update system.

TODO it is never clarified by what mechanism error are passed to the system.
TODO which errors should be passed to the system are never specified.

## Terminology

The following terms are used through out this document.

- **TUF**: Shorthand for The Update Framework, the framework described in this document.

- **target** (or **target file**): A file available for download through TUF. A target may be an archive, executable binary, or disk image.
  Targets are opaque to TUF and are all treated equally.

- **metadata** (or **metadata file**): A file that describes a target(s) or another metadata file(s).

- **role**: An entity, either human or automated, that generates and cryptographically signs a particular type of metadata.

- **repository**: A service that hosts TUF metadata and targets and make them available for download.

## Requirements Language

The keywords "MUST," "MUST NOT," "REQUIRED," "SHALL," "SHALL NOT," "SHOULD," "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

## Overview

TUF uses interlinked providers of metadata (roles) to create chains of trust so that attestations of the validity of given target can be delegated away from a single source.

The metadata describing targets is the information necessary to securely identify the target and indicate which roles are trusted to provide metadata about the target.
As providing additional information about targets may be important to some software update systems using TUF, additional arbitrary information can be provided with any target.
This information will be included in signed metadata that describes the target.

### High Level Update Procedure

The following are the high-level steps of using TUF from the viewpoint of a software update system in an error-free case.

The application using TUF instructs TUF to check for updated metadata.
If TUF reports to the application code that there is new metadata, then it is up to the application to determine whether it wants to download new targets.
Only targets that are fully trusted are made available to the application.

For each target that the application wants, it asks TUF to download the target.
TUF downloads the target and performs security checks to ensure that the downloaded target is exactly what is expected
according to the signed metadata.
The application is not given access to the target until the security checks have been completed.
At this point, the application has securely obtained a reference to the target and can do with it whatever it wishes.

# Data Interchange

TUF MUST make metadata available as JSON as described in {{RFC7159}}.
TUF MUST make this JSON available over HTTP as described in {{RFC2616}}.
TUF MAY use HTTPS instead of plain HTTP to serve content, but this is not required.
The absence of HTTPS does not degrade any of the security properties TUF provides.

# Cryptography

TUF uses established cryptographic protocols and algorithms as basis for the security guarantees it provides.

## Cryptographic Hash Functions {#hashes}

TUF uses cryptographic hash functions to compute digests of targets.
TUF does *not* specify any hash functions as mandatory since TUF may be used on devices with constrained CPUs, memory, or power.

TUF MAY use the SHA-256 or SHA-512 hash functions as described in {{RFC4634}} to calculate the digest for a target.

TUF SHOULD use hash functions with strong cryptographic properties.
Use of insecure hash functions weakens the security protections TUF provides.
For example, TUF SHOULD NOT use the md5 hash algorithm as described in {{RFC1321}}.

### Hashes Object {#hashes_object}

Some types of metadata specifies the output of a hash function applied over metadata files or targets.

`HASHES` is an object whose format MUST be the following:

~~~ json
{
   HASH_IDENTIFIER: HASH_VALUE,
   ...
}
~~~

`HASH_IDENTIFIER` MUST be a unique string that fully identifies the parameters to a hash function.
For example, the SHA-256 hash function MAY be identified by `sha256`.
For example, the `scrypt` hash function with parameters `n=10, r=8, p=1` and 256 bits of output MAY be identified by `scrypt-256bits-n10-r8-p1`.

`HASH_VALUE` MUST be the encoded value of the output of the hash function with the input being the metadata converted to bytes.

## Public Key Cryptography {#public_key_crypto}

TUF uses public key cryptography to sign metadata about targets and other metadata.
Like mentioned in {{hashes}}, TUF does *not* specify public key types or signing schemes as there may be limitations on devices that dictate which signing schemes may be used.

TUF MAY utilize the Ed25519 signing scheme as described in {{ED25519}}.
TUF MAY utilize RSA keys and their various signing schemes as described in {{RFC3447}} and {{RFC5756}}.

### Encoding Public Keys {#encoding_public_keys}

All keys MUST have the format:

~~~ json
{
  "keytype": KEYTYPE,
  "keyval": KEYVAL
}
~~~

where `KEYTYPE` is a string describing the type of the key.
The type determines the interpretation of `KEYVAL`.

We define two keytypes at present: 'rsa' and 'ed25519'.
RSA keys MUST be encoded with the PEM format.
TODO should specify PKCS#1, PKCS#8, or SPKI.
Ed25519 keys MUST be lower case hexadecimal encodings of the 32 bytes of the public key.

Both RSA and Ed25519 keys MUST use the `KEYVAL` format below.

~~~ json
{
  "public": PUBLIC
}
~~~

Where `PUBLIC` is the encoding described above.

### Calculating Key IDs {#calculating_key_ids}

To identify keys used in TUF's PKI, each key uses a deterministically calculated key ID that MUST be calculated in the following way.

~~~
key_id = id_encoding(sha256(cjson(encoded_public_key)))
~~~

Here, the `id_encoding` function MAY be one of: hexadecimal, base32, base64 (as described in {{RFC4648}}).
`sha256` is the SHA-256 hash function as described in {{RFC4634}}.
`cjson` is the function that takes a JSON entity as input and outputs bytes of canonical json.
`encoded_public_key` is a previously agreed upon encoding of the public component of the key pair.

Each implementation of TUF MUST NOT allow a public key to be encoded in multiple ways.
For example, an Ed25519 public key could be encoded with both base32 and base64 which would give a single key multiple key IDs.
Likewise, an RSA key could be PEM encoded in both SPKI, PKCS#1, and PKCS#8 giving it multiple key IDs.
This would degrade TUF's security guarantees.

A key's ID MUST be calculated by any client receiving metadata.
If a calculated KEYID does not match the one provided, then that key MUST NOT be used for verifying metadata or targets.
Clients MUST ensure that for any key ID in any metadata, only one unique key has that key ID.

## Canonical JSON

In order to verify signatures over the JSON metadata, TUF uses the Canonical JSON encoding scheme as described in {{CJSON}}.

# Roles

An implementer of TUF MUST provide the following roles:

- Root role ({{root_role}})
- Targets role ({{targets_role}})
- Snapshot role ({{snapshot_role}})
- Timestamp role ({{timestamp_role}})

An implementer MAY provide the following role:

- Mirrors role ({{mirrors_role}})

Collectively, these roles are referred to as "top-level roles."
Metadata provided by a role is referred to as "ROLE metadata" for convenience.
For example, metadata provided by the root role is called "root metadata."

These roles use hash algorithms as described in {{hashes}} and signing schemes as described in {{public_key_crypto}}.

All metadata provided by these roles is JSON and MUST use the following format:

~~~ json
{
  "signaures": [ SIGNATURE_OBJECT, ... ],
  "signed": { ... }
}
~~~

Where the `SIGNATURE_OBJECT` MUST use the following format.

~~~ json
{
  "keyid": KEY_ID,
  "method": METHOD,
  "sig": SIGNATURE
}
~~~

Here `KEY_ID` is a string calculated from the public component of a key pair as described in {{calculating_key_ids}}.
`METHOD` is a string describing the signature method used to generate the signature, such as `ed25519` or `rsassa-pss-sha512`.
`SIGNATURE` is an encoded signature, where the encoding is previously agreed upon and MAY be hexadecimal or base64.

The `signed` object is the metadata provided by any role.
The format of the metadata each role provides will be discussed in its respective section.

Some fields that all metadata shares is as follows.
Details will be discussed in later sections.

- `_type`: The identifier of the type of metadata (e.g., "root" or "snapshot")
- `expires`: The timestamp for when this metadata should be considered untrusted
- `version`: A number the constantly increments to identify which version the metadata is

Metadata timestamp data MUST follow the  ISO 8601 standard.
The expected format of the combined date and time string MUST be `YYYY-MM-DDTHH:MM:SSZ`.
Time MUST be in UTC, and the "Z" time zone designator is attached to indicate a zero UTC offset.
An example date-time string is `1985-10-21T01:21:00Z`.

## Root Role {#root_role}

The root role delegates trust to specific keys trusted for all other top-level roles used in the system.
The root role's private keys need to be kept very secure and SHOULD be kept offline.

To start the chain of trust, the client-side of TUF MUST include one of the two following items:

- The first version of the root metadata
- `N` key IDs where `N` is greater than or equal to the threshold of keys required to trust the root metadata

TODO explain why the second option is sufficient and how an implementation MUST verify the first downloaded root metadata.

### Root Metadata

The `signed` portion of the root metadata MUST use the following format.

~~~ json
{
  "_type": "Root",
  "version": VERSION,
  "expires": EXPIRES,
  "keys": {
    KEYID: KEY,
    ...
  },
  "roles": {
    ROLE: {
      "keyids": [ KEYID, ... ],
      "threshold": THRESHOLD
    },
    ...
  }
}
~~~

`VERSION` is an integer that MUST be greater than 0.
A repository SHOULD start number all metadata with version 1 and increment by 1 for each update.
Clients MUST NOT replace a metadata file with a version number less than the one currently trusted.
TODO explain how to recover from compromised root keys (if even possible).

`EXPIRES` determines when metadata should be considered expired and no longer trusted by clients.
Clients MUST NOT trust expired root metadata, and thus MUST NOT trust metadata authorized by roles in the root metadata.
TODO explain trusting during rebuilding the chain of trust.

A `ROLE` is one of `Root`, `Snapshot`, `Targets`, `Timestamp`, or `Mirrors`.
A role for each of `Root`, `Snapshot`, `Timestamp`, and `Targets` MUST be specified in the key list.
The role of `Mirror` is OPTIONAL.

The `KEY` object is as described in {{encoding_public_keys}}.

Clients MUST calculate each `KEYID` to verify this is correct for the associated key.

The `THRESHOLD` for a role is an integer of the number of keys of that role whose valid signatures are required in order to consider a file as trusted.
All threshold holds MUST be strictly greater than zero.

## Targets Role {#targets_role}

The targets role generates and signs metadata that includes information about what targets are available for download.
This metadata includes the hashes and lengths of the targets that are available.
The targets role does not sign targets themselves.

To allow multiple entities to sign metadata about different targets, the targets top-level role may delegate the signing of a particular target or set of targets to a "delegated targets role."
This role itself is structure identically to the top-level targets role and may delegate signing to further delegated targets roles.

TODO specify delegated roles need to be prefixed with the path that leads to them e.g., role A has sub role B, then that's at A/B

### Targets Metadata

The `signed` portion of targets metadata MUST use the following format.

~~~ json
{
  "_type": "Targets",
  "version": VERSION,
  "expires": EXPIRES,
  "targets": TARGETS,
  "delegations": DELEGATIONS
}
~~~

`EXPIRES` determines when metadata should be considered expired and no longer trusted by clients.
Thus, targets and delegations listed in the targets metadata MUST NOT be trusted if the targets metadata has expired.

`VERSION` is an integer that MUST be greater than 0.

The `DELEGATIONS` field is OPTIONAL and is described in {{targets_delegations}}.

`TARGETS` is an object whose format MUST be the following:

~~~ json
{
  TARGETPATH: {
    "length": LENGTH,
    "hashes": HASHES,
    ("custom": { ... })
  },
  ...
}
~~~

Each key of the `TARGETS` object is a `TARGETPATH`.
A `TARGETPATH` is a path to a file that is relative to a mirror's base URL of targets.
A `TARGETPATH` MUST NOT include the component `..`.
That is, the `TARGETPATH` `foo/../bar/` is not allowed, but `..foo/bar/` is allowed.

`LENGTH` MUST be an inclusive upper bound on the size of the metadata file.

`HASHES` is an object as described in {{hashes_object}}.

A `TARGETS` object MAY have no `TARGETPATH` elements.
This indicates that no target files are available.

The field `custom` is OPTIONAL.
`custom` MAY be in any JSON value, such as object or string.
If defined, the elements and values of `custom` will be made available to the client application.
The information in `custom` is opaque to TUF and MUST NOT be used by TUF to influence TUF's behavior.
`custom` MAY include version numbers, dependencies, requirements, and any other data that the application wants to include to describe the file at `TARGETPATH`.
The application MAY use this information to guide download decisions.

### Targets Delegations {#targets_delegations}

Targets delegations are used to allow for the responsibility of attesting the validity of a target or targets to be offloaded to another role with another set of keys.

These delegations may be nested such that some metadata `A` points to `B` which points to `C` and so on.
For a target listed in any piece of metadata to be valid, all metadata tracing up the chain back to the target metadata and then root metadata MUST be valid according to that metadata's rules for validity.

#### Targets Delegation Metadata

If defined, `DELEGATIONS` is an object whose format MUST be the following:

~~~ json
{
  "keys": {
    KEYID: KEY,
    ...
  },
  "roles": [
    {
      "name": ROLENAME,
      "keyids": [ KEYID, ... ],
      "threshold": THRESHOLD,
      ("path_hash_prefixes": [ HEX_DIGEST, ... ] |
       "paths": [ PATHPATTERN, ... ])
    },
    ...
  ]
}
~~~

`keys` is an objet whoes keys are key IDs calculated as described in {{calculating_key_ids}}.
The `KEY` object MUST be the format as described in {{encoding_public_keys}}.

`ROLENAME` is the full name of the delegated role.
For example, `delegations/foo`.
TODO should we say: All delegations SHOULD have a common prefix such as "delegations"

The targets delegation metadata for any `ROLENAME` is located at `ROLENAME.json` relative to the base URL.
The format of targets delegation metadata is exactly the metadata of the targets role.
This implies that the `targets.json` can delegate to `delegation/a.json` which itself can delegate to `delegation/b.json`.
TODO require tree structure or require cycle checking?

The `keyids` field contains a list of keys authorized to sign for a given role.
These key IDs are calculated as described in {{calculating_key_ids}}.

The `THRESHOLD` for a role is an integer of the number of keys of that role whose valid signatures are required in order to consider a file as trusted.
All threshold holds MUST be strictly greater than zero.

`DELEGATIONS` MUST include either `paths` or `path_hash_prefixes`, but not both.

The `paths" list describes paths that the role is trusted to provide.
Clients MUST check that a target is in one of the trusted paths of all roles in a delegation chain, not just in a trusted path of the role that describes
the target file.

The format of a `PATHPATTERN` may be either a path to a single file, or a path to a directory to indicate all files and/or subdirectories under that directory.

A path to a directory is used to indicate all possible targets sharing that directory as a prefix.
For example, if the directory is `targets/A`, then targets which match that directory include `targets/A/B.pkg` and `targets/A/B/C.pkg`.

The `path_hash_prefixes` list is used to succinctly describe a set of target paths.
Specifically, each i`HEX_DIGEST` in `path_hash_prefixes` describes a set of target paths
Therefore, `path_hash_prefixes` is the union over each prefix of its set of target paths.
The target paths MUST meet this condition: each target path, when hashed with the SHA-256 hash function to produce a 64-byte hexadecimal digest (`HEX_DIGEST`), must share the same prefix as one of the prefixes in `path_hash_prefixes`.
This is useful to split a large number of targets into separate bins identified by consistent hashing.

TODO should priority tags be in the spec?

We are currently investigating a few "priority tag" schemes to resolve conflicts between delegated roles that share responsibility for overlapping target paths.
One of the simplest of such schemes is for the client to consider metadata in order of appearance of delegations.
We treat the order of delegations such that the first delegation is trusted more than the second one, the second delegation is trusted more than the third one, and so on.
The metadata of the first delegation will override that of the second delegation, the metadata of the second delegation will override that of the third delegation, and so on.
In order to accommodate this scheme, the `roles` key in the `DELEGATIONS` object above points to an array, instead of a hash table, of delegated roles.

Another priority tag scheme would have the clients prefer the delegated role with the latest metadata for a conflicting target path.
Similar ideas were explored in the Stork package manager ([University of Arizona Tech Report 08-04](https://isis.poly.edu/~jcappos/papers/cappos_stork_dissertation_08.pdf)).

## Snapshot Role {#snapshot_role}

The snapshot role signs metadata that provides information about the latest version of all of the other metadata on the repository (excluding the timestamp metadata).
This information allows clients to know which metadata files have been updated and also prevents mix-and-match attacks.

The information about the timestamp metadata MUST NOT be included in the snapshot metadata.
For all other metadata, the version number MUST be included.
For all versions of the root role, the hash(es) and size MUST be included.
For all other metadata, the hash(es) and size MAY be included.

### Snapshot Metadata

The `signed` portion of of that snapshot metadata MUST use the following format.

~~~ json
{
  "_type": "Snapshot",
  "version": VERSION,
  "expires": EXPIRES,
  "meta": METAFILES
}
~~~

`VERSION` is an integer that MUST be greater than 0.

`EXPIRES` determines when metadata should be considered expired and no longer trusted by clients.
Thus, metadata listed in snapshot metadata MUST NOT be trusted if the snapshot metadata has expired.

`METAFILES` is an object whose format MUST be the following:

TODO should metadata listed in snapshot metadata be trusted if and only if snapshot has not expired?

~~~ json
{
  METAPATH: {
    "length": LENGTH,
    "hashes": HASHES,
    "version": VERSION
  },
  ...
}
~~~

`METAPATH` MUST be the metadata file's path on the repository relative to the base URL.

`LENGTH` MUST be an inclusive upper bound on the size of the metadata file at `METAPATH`.
The length MAY be exactly the size of the file, or it MAY be larger to allow for the serving of compressed files.
TODO should compressed metadata be allowed?

`VERSION` MUST be the current version of the metadata at `METAPATH`.

`HASHES` is an object as described in {{hashes_object}} calculated over the file at `METAPATH`.

## Timestamp Role {#timestamp_role}

The timestamp role signs metadata describing the metadata provided by snapshot role.
The timestamp role SHOULD have short expirations on the validity of its metadata and use an automated process to continuously sign new metadata.
Keeping the timestamp role's private keys online poses minimal threats to the client in the event of key compromise.

### Timestamp Metadata

The `signed` portion of timestamp metadata MUST use the following format.

~~~ json
{
  "_type": "Timestamp",
  "version": VERSION,
  "expires": EXPIRES,
  "meta": METAFILES
 }
~~~

`EXPIRES` determines when metadata should be considered expired and no longer trusted by clients.

`VERSION` is an integer that MUST be greater than 0.

`EXPIRES` determines when metadata should be considered expired and no longer trusted by clients.
Thus, metadata listed in snapshot metadata MUST NOT be trusted if the snapshot metadata has expired.

`METAFILES` is an object whose format MUST be the following:

TODO should metadata listed in timestamp metadata be trusted if and only if timestamp has not expired?

~~~ json
{
  METAPATH: {
    "length": LENGTH,
    "hashes": HASHES,
    "version": VERSION
  },
  ...
}
~~~

`METAPATH` MUST be the metadata file's path on the repository relative to the base URL.

## Mirrors Role {#mirrors_role}

Every repository has one or more mirrors from which files can be downloaded by clients.
An application using TUF MAY hard-code the mirror information in their software or they MAY use mirror metadata files that are signed by a mirrors role.

The importance of using signed mirror lists depends on the application and the users of that application.
There is minimal risk to the application's security from contacting the wrong mirrors.
This is because TUF has very little trust in repositories.

### Mirrors Metadata

TODO this whole section

The `signed` portion of mirrors metadata MUST use the following format.

~~~ json
{
  "_type": "Mirrors",
  "version": VERSION,
  "expires": EXPIRES,
  "mirrors": [
    {
      "urlbase": URLBASE,
      "metapath": METAPATH,
      "targetspath": TARGETSPATH,
      "metacontent": [ PATHPATTERN ... ] ,
      "targetscontent": [ PATHPATTERN ... ] ,
      ("custom": { ... })
    },
    ...
  ]
}
~~~

URLBASE is the URL of the mirror which METAPATH and TARGETSPATH are relative to.
All metadata files will be retrieved from METAPATH and all target files will be retrieved from TARGETSPATH.

The lists of PATHPATTERN for "metacontent" and "targetscontent" describe the metadata files and target files available from the mirror.

The order of the list of mirrors is important.
For any file to be downloaded, whether it is a metadata file or a target file, TUF on the client will give priority to the mirrors that are listed first.
That is, the first mirror in the list whose "metacontent" or "targetscontent" include a path that indicate the desired file can be found there will the first mirror that will be used to download that file.
Successive mirrors with matching paths will only be tried if downloading from earlier mirrors fails.
This behavior can be modified by the client code that uses TUF to, for example, randomly select from the listed mirrors.

# Repositories

An application uses TUF to interact with one or more repositories.
Each repository is a collection of one or more mirrors which are the actual providers of files to be downloaded.

Consider the repository for all packages of the Example programming language.
This repository may have only one "mirror," name the primary repository itself located at `http://tuf.example.com`.

A mirror is a full mirror if it provides all targets available on the repository, otherwise it is a partial mirror.
If a mirror is intended to only act as a partial mirror, the metadata and target paths available from that mirror can be specified.

An application MAY use multiple repositories to download files.
For example, [Maven](https://maven.apache.org/) provides the option to download JARs from multiple locations.
If these were TUF repositories, they would each have their own root of trust and root metadata.

Roles, trusted keys, and target files are completely separate between repositories.
A multi-repository setup is a multi-root system.
When an application uses TUF with multiple repositories, TUF MUST NOT mix the trusted content from each repository.
It is up to the application to determine the significance of the same or different target files provided from separate repositories.

TODO explain mixing of trusted content better

## Repository Layout

Repositories use a filesystem like lay out.
This is done for two purposes:

- To give mirrors an easy way to mirror only some of the repository
- To specify which parts of the repository a given role has authority to sign/provide

### Target Files

The filenames and the directory structure of target files available from a repository are not specified by TUF.
The names of these files and directories are completely at the discretion of the application using TUF.

### Metadata Files

The filenames and directory structure of repository metadata are strictly defined.
The following metadata files of top-level roles MUST be made available relative to the base URL of metadata for a repository mirror.

- `/root.json` for the root metadata
- `/targets.json` for the targets metadata
- `/timestamp.json` for the timestamp metadata
- `/snapshot.json` for the snapshot metadata

If the mirrors role is used, then the mirrors MUST similarly be made available at `/mirrors.json`.

An implementation of TUF may OPTIONALLY choose to make available any metadata files in compressed format such as GZIP.
In doing so, the filename of the compressed file MUST be the same as the original with the addition of the file name extension for the compression type (e.g. snapshot.json.gz).
The original, uncompressed file MUST always be made available.

#### Metadata Files for Delegated Targets

When the targets role delegates trust to other roles, each delegated role provides one signed metadata file.
As is the case with the directory structure of top-level metadata, the delegated files are relative to the base URL of metadata available from a given repository mirror.

A delegated targets metdata file for a role `DELEGATED_ROLE` MUST be available at the relative URL `/DELEGATED_ROLE.json`.
If this role further delegates trust to a role named `ANOTHER_ROLE`, that role's signed metadata file MUST be available at the URL relative to the root `/ANOTHER_ROLE.json`.
Roles MAY contain a slash (`/`) in their name.
For example, the role `foo/bar` would have its metadata available at `/foo/bar.json`.

# Detailed Workflows

## Updating Metadata and Downloading Targets

The following sub sections provide an ordered list of steps a TUF client MUST follow in order to download and verify metadata and targets.

### Load Previous Root Metadata

The client MUST NOT use the `expires` field when validating the root metadata during this step.
That is, during this step, root metadata is allowed to be expired.

If the TUF client has a previously trusted root metadata file, then the TUF client MUST load it and verify that is has a valid signatures greater than or equal to the threshold set for the root role in the signed portion.
If there is an insufficient number of valid signatures, then the client MUST flush this metadata and abort.
If there is a sufficient number of valid signatures, the client proceeds to {{update_root_metadata}}

If the TUF client has no previously trusted root metadata file, and the TUF client has a set of trusted key IDs, then the client MUST download the metadtafile `1.root.json` and verify it using only the keys that have IDs in the set of trusted key IDs.
If there is an insufficient number of valid signatures, then the client MUST flush this metadata and abort.
If there is a sufficient number of valid signatures, the client proceeds to {{update_root_metadata}}

### Update the Root Metadata {#update_root_metadata}

The client MUST download the metadata `root.json`.
If the client's current trusted version of the root metadata is at version `N` and the `root.json` version `M`, client MUST take the following steps.

#### N = M

The current metadata is up to date, and the client proceeds to {{update_timestamp_metadata}}.

#### N > M

There current metadata is ahead of what the repository is reporting.
TODO explain steps.

#### N &lt; M

For every version `X` in the set `(N, N+1, ... , M-1, M)`, the client MUST take the following steps.

##### Download X.root.json

The TUF client MUST have a known value `Y` that is the maximum size in bytes of a root metadata file.

The client downlods `X.root.json` up to `Y` bytes.
If `Y` bytes is exceeded, the client MUST abort and report this error back to the application.
If this file is not available, TODO.

##### Verify X.root.json

The metadata `X.root.json` MUST have:

1) A number `A` valid signatures from keys in `(X-1).root.json` where `A` is the threshold of the root role set in `(X-1).root.json`.
   If `X = 1`, then only use the next step.
2) A number `B` valid signatures from keys in `X.root.json` where `B` is the threshold of the root role set in `X.root.json`.

TODO how to abort? Are we allowed to continue because it might rotate the keys where none of the tresholds of metadata are impacted by what the client currently knows?

##### Verify X.root.json is Version X

If the version in the signed portion of the root metadata is not also `X`, then the client MUST (TODO) and abort(?).

##### Verify X.root.json Has Not Expired

If `X = M` and current time is not before the `expires` field in the signed portion of the metadata, then the client MUST abort.
TODO explain more?

##### Set Root Metadata

If this step has been reached, then the client MUST save the `X.root.json` as the latest trusted root metadata.

##### Flush Old Metadata

For each non-root top-level role, iff any of the keys for the role have been rotated, then the client MUST flush all keys, metadata, and files associated with that role.

An explanation for this step can be found in the {{MERCURY}} paper.

## Update the Timestamp Metadata {#update_timestamp_metadata}

### Download the Timestamp Metadata

The TUF client MUST have a known value `X` that is the maximum size in bytes of a timestamp metadata file.

The client downlods `timestamp.json` up to `X` bytes.
If `X` bytes is exceeded, the client MUST abort and report this error back to the application.
If this file is not available, TODO.

### Verify the Timestamp Metadata
2.1. **Check signatures.** The timestamp metadata file must have been
signed by a threshold of keys specified in the root metadata file.

2.2. **Check for a rollback attack.** The version number of the previous
timestamp metadata file, if any, must be less than or equal to the version
number of this timestamp metadata file.

2.3. **Check for a freeze attack.** The latest known time should be lower
than the expiration timestamp in this metadata file.

3. **Download and check the snapshot metadata file**, up to the number of
bytes specified in the timestamp metadata file.
If consistent snapshots are not used (see Section 7), then the filename
used to download the snapshot metadata file is of the fixed form
FILENAME.EXT (e.g., snapshot.json).
Otherwise, the filename is of the form VERSION.FILENAME.EXT (e.g.,
42.snapshot.json), where VERSION is the version number of the snapshot
metadata file listed in the timestamp metadata file.  In either case,
the client MUST write the file to non-volatile storage as
FILENAME.EXT.

3.1. **Check against timestamp metadata.** The hashes, and version number
of this metadata file MUST match the timestamp metadata.

3.2. **Check signatures.** The snapshot metadata file MUST have been signed
by a threshold of keys specified in the previous root metadata file.

3.3. **Check for a rollback attack.**

3.3.1. Note that the previous snapshot metadata file may be checked for
authenticity, but its expiration does not matter for the following
purposes.

3.3.2. The version number of the previous snapshot metadata file, if any,
MUST be less than or equal to the version number of this snapshot metadata
file.

3.3.3. The version number of the targets metadata file, and all delegated
targets metadata files (if any), in the previous snapshot metadata file, if
any, MUST be less than or equal to its version number in this snapshot
metadata file. Furthermore, any targets metadata filename that was listed
in the previous snapshot metadata file, if any, MUST continue to be listed
in this snapshot metadata file.

3.4. **Check for a freeze attack.** The latest known time should be lower
than the expiration timestamp in this metadata file.

4. **Download and check the top-level targets metadata file**, up to either
the number of bytes specified in the snapshot metadata file, or some
Z number of bytes. The value for Z is set by the authors of the application
using TUF. For example, Z may be tens of kilobytes.
If consistent snapshots are not used (see Section 7), then the filename
used to download the targets metadata file is of the fixed form
FILENAME.EXT (e.g., targets.json).
Otherwise, the filename is of the form VERSION.FILENAME.EXT (e.g.,
42.targets.json), where VERSION is the version number of the targets
metadata file listed in the snapshot metadata file.
In either case, the client MUST write the file to non-volatile storage as
FILENAME.EXT.

4.1. **Check against snapshot metadata.** The hashes (if any), and version
number of this metadata file MUST match the snapshot metadata. This is
done, in part, to prevent a mix-and-match attack by man-in-the-middle
attackers.

4.2. **Check for an arbitrary software attack.** This metadata file MUST
have been signed by a threshold of keys specified in the latest root
metadata file.

4.3. **Check for a rollback attack.** The version number of the previous
targets metadata file, if any, MUST be less than or equal to the version
number of this targets metadata file.

4.4. **Check for a freeze attack.** The latest known time should be lower
than the expiration timestamp in this metadata file.

4.5. **Perform a preorder depth-first search for metadata about the desired
target, beginning with the top-level targets role.**

4.5.1. If this role has been visited before, then skip this role (so that
cycles in the delegation graph are avoided).
Otherwise, if an application-specific maximum number of roles have been
visited, then go to step 5 (so that attackers cannot cause the client to
waste excessive bandwidth or time).
Otherwise, if this role contains metadata about the desired target, then go
to step 5.

4.5.2. Otherwise, recursively search the list of delegations in order of
appearance.

4.5.2.1. If the current delegation is a multi-role delegation, recursively
visit each role, and check that each has signed exactly the same non-custom
metadata (i.e., length and hashes) about the target (or the lack of any
such metadata).

4.5.2.2. If the current delegation is a terminating delegation, then jump
to step 5.

4.5.2.3. Otherwise, if the current delegation is a non-terminating
delegation, continue processing the next delegation, if any. Stop the
search, and jump to step 5 as soon as a delegation returns a result.

5. **Verify the desired target against its targets metadata.**

5.1. If there is no targets metadata about this target, then report that
there is no such target.

5.2. Otherwise, download the target (up to the number of bytes specified in
the targets metadata), and verify that its hashes match the targets
metadata. (We download up to this number of bytes, because in some cases,
the exact number is unknown. This may happen, for example, if an external
program is used to compute the root hash of a tree of targets files, and
this program does not provide the total size of all of these files.)
If consistent snapshots are not used (see Section 7), then the filename
used to download the target file is of the fixed form FILENAME.EXT (e.g.,
foobar.tar.gz).
Otherwise, the filename is of the form HASH.FILENAME.EXT (e.g.,
c14aeb4ac9f4a8fc0d83d12482b9197452f6adf3eb710e3b1e2b79e8d14cb681.foobar.tar.gz),
where HASH is one of the hashes of the targets file listed in the targets
metadata file found earlier in step 4.
In either case, the client MUST write the file to non-volatile storage as
FILENAME.EXT.

# Key Management and Migration

All keys, except those for the timestamp and mirrors roles, should be
stored securely offline (e.g. encrypted and on a separate machine, in
special-purpose hardware, etc.).  This document does not prescribe how keys
should be encrypted and stored, and so it is left to implementers of
this document to decide how best to secure them.

To replace a compromised root key or any other top-level role key, the root
role signs a new root.json file that lists the updated trusted keys for the
role.  When replacing root keys, an application will sign the new root.json
file with both the new and old root keys. Any time such a change is
required, the root.json file is versioned and accessible by version number,
e.g., 3.root.json. Clients update the set of trusted root keys by requesting
the current root.json and all previous root.json versions, until one is
found that has been signed by a threshold of keys that the client already
trusts. This is to ensure that outdated clients remain able to update,
without requiring all previous root keys to be kept to sign new root.json
metadata.

In the event that the keys being updated are root keys, it is important to
note that the new root.json must at least be signed by the keys listed as
root keys in the previous version of root.json, up to the threshold listed
for root in the previous version of root.json. If this is not the case,
clients will (correctly) not validate the new root.json file.  For example,
if there is a 1.root.json that has threshold 2 and a 2.root.json that has
threshold 3, 2.root.json MUST be signed by at least 2 keys defined in
1.root.json and at least 3 keys defined in 2.root.json. See step 1 in
Section 5.1 for more details.

To replace a delegated developer key, the role that delegated to that key
just replaces that key with another in the signed metadata where the
delegation is done.

# Consistent Snapshots

So far, we have considered a TUF repository that is relatively static (in
terms of how often metadata and target files are updated). The problem is
that if the repository (which may be a community repository such as PyPI,
RubyGems, CPAN, or SourceForge) is volatile, in the sense that the
repository is continually producing new TUF metadata as well as its
targets, then should clients read metadata while the same metadata is being
written to, they would effectively see denial-of-service attacks.
Therefore, the repository needs to be careful about how it writes metadata
and targets. The high-level idea of the solution is that each snapshot will
be contained in a so-called consistent snapshot. If a client is reading
from one consistent snapshot, then the repository is free to write another
consistent snapshot without interrupting that client. For more reasons on
why we need consistent snapshots, please see
https://github.com/theupdateframework/pep-on-pypi-with-tuf#why-do-we-need-consistent-snapshots

## Writing consistent snapshots

We now explain how a repository should write metadata and targets to
produce self-contained consistent snapshots.

Simply put, TUF should write every metadata file as such: if the
file had the original name of filename.ext, then it should be written to
non-volatile storage as version_number.filename.ext, where version_number
is an integer.

On the other hand, consistent target files should be written to
non-volatile storage as digest.filename.ext.  This means that if the
referrer metadata lists N cryptographic hashes of the referred file, then
there must be N identical copies of the referred file, where each file will
be distinguished only by the value of the digest in its filename. The
modified filename need not include the name of the cryptographic hash
function used to produce the digest because, on a read, the choice of
function follows from the selection of a digest (which includes the name of
the cryptographic function) from all digests in the referred file.

Additionally, the timestamp metadata (timestamp.json) should also be
written to non-volatile storage whenever it is updated. It is optional for
an implementation to write identical copies at digest.timestamp.json for
record-keeping purposes, because a cryptographic hash of the timestamp
metadata is usually not known in advance. The same step applies to the root
metadata (root.json), although an implementation must write both root.json
and digest.root.json because it is possible to download root metadata both
with and without known hashes. These steps are required because these are
the only metadata files that may be requested without known hashes.

Most importantly, no metadata file format must be updated to refer to the
names of metadata or target files with their hashes included. In other
words, if a metadata file A refers to another metadata or target file B as
filename.ext, then the filename must remain as filename.ext and not
digest.filename.ext. This rule is in place so that metadata signed by roles
with offline keys will not be forced to sign for the metadata file whenever
it is updated. In the next subsection, we will see how clients will
reproduce the name of the intended file.

Finally, the root metadata should write the Boolean "consistent_snapshot"
attribute at the root level of its keys of attributes. If consistent
snapshots are not written by the repository, then the attribute may either
be left unspecified or be set to the False value.  Otherwise, it must be
set to the True value.

## Reading consistent snapshots

TODO

# Configuring a TUF client

TODO max root size

TODO min download speed

# Side Channel Attacks

TODO attacks against NTP = broken TUF metadata

# Acknowledgements

Work on TUF began in late 2009.
The core ideas are based off of previous work done by Justin Cappos and Justin Samuel that identified security flaws in all popular Linux package managers.

The Global Environment for Network Innovations ([GENI](https://www.geni.net/)) and the National Science Foundation ([NSF](https://www.nsf.gov/)) have
provided support for the development of TUF.

TUF's reference implementation is based heavily on Thandy, the application updater for [Tor](https://torproject.org).
Its design and this spec are also largely based on Thandy's, with many parts being directly borrowed from Thandy.
Thandy is the hard work of Nick Mathewson, Sebastian Hahn, Roger Dingledine, Martin Peck, and others.
