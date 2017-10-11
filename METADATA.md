# Metadata

Metadata files provide information that clients can use to make update decisions. Different metadata files provide different information. The various metadata files are signed by different keys as are indicated by the root role. The concept of roles allows TUF to only trust information that a role is trusted to provide.

The signed metadata files always include the time they were created and their expiration dates. This ensures that outdated metadata will be detected and that clients can refuse to accept metadata older than that which they've already seen.

All TUF metadata uses a subset of the JSON object format. When calculating the digest of an object, we use the [Canonical JSON](http://wiki.laptop.org/go/Canonical_JSON) format. Implementation-level detail about the metadata can be found in the [spec](docs/tuf-spec.txt).

There are four required top-level roles and one optional top-level role, each with their own metadata file.

Required:

* Root
* Targets
* Snapshot
* Timestamp

Optional:

* Mirrors (unimplemented)

There may also be any number of delegated target roles.

## Root Metadata (root.json)

Signed by: Root role.

Specifies the other top-level roles. When specifying these roles, the trusted keys for each role are listed along with the minimum number of those keys which are required to sign the role's metadata. We call this number the signature threshold.

See [example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/root.json) of Root metadata.

## Targets Metadata (targets.json)

Signed by: Targets role.

The targets.json metadata file lists hashes and sizes of target files. Target files are the actual files that clients are intending to download (for example, the software updates they are trying to obtain).

This file can optionally define other roles to which it delegates trust. Delegating trust means that the delegated role is trusted for some or all of the target files available from the repository. When delegated roles are specified, they are specified in a similar way to how the Root role specifies the top-level roles: the trusted keys and signature threshold for each role is given. Additionally, one or more patterns are specified which indicate the target file paths for which clients should trust each delegated role.

See [example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/targets.json) of Targets metadata.

## Delegated Targets Metadata (role1.json)

Signed by: A delegated targets role.

The metadata files provided by delegated targets roles follow exactly the same format as the metadata file provided by the top-level Targets role.

When the targets role delegates trust to other roles, each delegated role provides one signed metadata file.  As is the
case with the directory structure of top-level metadata, the delegated files are relative to the base URL of metadata available from a given repository mirror.

A delegated role file is located at:

/DELEGATED_ROLE.json

where DELEGATED_ROLE is the name of the delegated role that has been specified in targets.json.  If this role further delegates trust to a role named ANOTHER_ROLE, that role's signed metadata file is made available at:

/ANOTHER_ROLE.json

See
[example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/role1.json)
of delegated Targets metadata and [example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/role2.json) of a nested delegation.

## snapshot Metadata (snapshot.json)

Signed by: Snapshot role.

The snapshot.json metadata file lists hashes and sizes of all metadata files other than timestamp.json. This file ensures that clients will see a consistent view of the files on the repository. That is, metadata files (and thus target file) that existed on the repository at different times cannot be combined and presented to clients by an attacker.

​See [example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/snapshot.json) of Snapshot metadata.

## Timestamp Metadata (timestamp.json)

Signed by: Timestamp role.

The timestamp.json metadata file lists the hashes and size of the snapshot.json file. This is the first and potentially only file that needs to be downloaded when clients poll for the existence of updates. This file is frequently resigned and has a short expiration date, thus allowing clients to quickly detect if they are being prevented from obtaining the most recent metadata. An online key is generally used to automatically resign this file at regular intervals.

There are two primary reasons why the timestamp.json file doesn't contain all of the information that the snapshot.json file does.

* The timestamp.json file is downloaded very frequently and so should be kept as small as possible, especially considering that the snapshot.json file grows in size in proportion to the number of delegated target roles.
* As the Timestamp role's key is an online key and thus at high risk, separate keys should be used for signing the snapshot.json metadata file so that the Snapshot role's keys can be kept offline and thus more secure.

See [example](https://raw.githubusercontent.com/theupdateframework/tuf/develop/tests/repository_data/repository/metadata/timestamp.json) of Timestamp metadata.

## Mirrors Metadata (mirrors.json)

Optionally signed by: Mirrors role.

The mirrors.json file provides an optional way to provide mirror list updates to TUF clients. Mirror lists can alternatively be provided directly by the software update system and obtained in any way the system sees fit, including being hard coded if that is what an applications wants to do.

No example available. At the time of writing, this hasn't been implemented in
TUF. Currently mirrors are specified by the client code.
