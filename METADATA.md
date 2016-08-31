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

Note:  Metadata content and name out-of-date.
See [example](http://mirror1.poly.edu/test-pypi/metadata/root.txt).

## Targets Metadata (targets.json)

Signed by: Targets role.

The targets.json metadata file lists hashes and sizes of target files. Target files are the actual files that clients are intending to download (for example, the software updates they are trying to obtain).

This file can optionally define other roles to which it delegates trust. Delegating trust means that the delegated role is trusted for some or all of the target files available from the repository. When delegated roles are specified, they are specified in a similar way to how the Root role specifies the top-level roles: the trusted keys and signature threshold for each role is given. Additionally, one or more patterns are specified which indicate the target file paths for which clients should trust each delegated role.

Note:  Metadata content and name out-of-date.
See [example](http://mirror1.poly.edu/test-pypi/metadata/targets.txt).

## Delegated Targets Metadata (targets/foo.json)

Signed by: A delegated targets role.

The metadata files provided by delegated targets roles follow exactly the same format as the metadata file provided by the top-level Targets role.

The location of the metadata file for each delegated target role is based on the delegation ancestry of the role. If the top-level Targets role defines a role named foo, then the delegated target role's full name would be targets/foo and its metadata file will be available on the repository at the path targets/foo.json (this is relative to the base directory from which all metadata is available). This path is just the full name of the role followed by a file extension.

If this delegated role foo further delegates to a role bar, then the result is a role whose full name is targets/foo/bar and whose signed metadata file is made available on the repository at targets/foo/bar.json.

Note:  Metadata content and name out-of-date.
See [example](http://mirror1.poly.edu/test-pypi/metadata/targets/unclaimed.txt).

## snapshot Metadata (snapshot.json)

Signed by: Snapshot role.

The snapshot.json metadata file lists hashes and sizes of all metadata files other than timestamp.json. This file ensures that clients will see a consistent view of the files on the repository. That is, metadata files (and thus target file) that existed on the repository at different times cannot be combined and presented to clients by an attacker.

Note:  Metadata content and name out-of-date.
​See [example](http://mirror1.poly.edu/test-pypi/metadata/release.txt).

## Timestamp Metadata (timestamp.json)

Signed by: Timestamp role.

The timestamp.json metadata file lists the hashes and size of the snapshot.json file. This is the first and potentially only file that needs to be downloaded when clients poll for the existence of updates. This file is frequently resigned and has a short expiration date, thus allowing clients to quickly detect if they are being prevented from obtaining the most recent metadata. An online key is generally used to automatically resign this file at regular intervals.

There are two primary reasons why the timestamp.json file doesn't contain all of the information that the snapshot.json file does.

* The timestamp.json file is downloaded very frequently and so should be kept as small as possible, especially considering that the snapshot.json file grows in size in proportion to the number of delegated target roles.
* As the Timestamp role's key is an online key and thus at high risk, separate keys should be used for signing the snapshot.json metadata file so that the Snapshot role's keys can be kept offline and thus more secure.

Note:  Metadata content and name out-of-date.
See [example](http://mirror1.poly.edu/test-pypi/metadata/timestamp.txt).

## Mirrors Metadata (mirrors.json)

Optionally signed by: Mirrors role.

The mirrors.json file provides an optional way to provide mirror list updates to TUF clients. Mirror lists can alternatively be provided directly by the software update system and obtained in any way the system sees fit, including being hard coded if that is what an applications wants to do.

No example available. At the time of writing, this hasn't been implemented in TUF. Currently mirrors are specified by the client code. 
