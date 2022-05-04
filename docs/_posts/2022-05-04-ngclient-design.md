---
title: "What's new in Python-TUF ngclient?"
author: Jussi Kukkonen
---

We recently released a new TUF client implementation, `ngclient`, in Python-TUF. This post explains why we ended up doing that when a client already existed.

# Simpler implementation, "correct" abstractions

The legacy code had a few problems that could be summarized as non-optimal abstractions: Significant effort had been put to code re-use, but not enough attention had been paid to ensure the expectations and promises of that shared code were the same in all cases of re-use. This combined with Pythons type ambiguity, use of dictionaries as "blob"-like data structures and extensive use of global state meant touching the shared functions was a gamble: there was no way to be sure something wouldn't break.

During the redesign, we really concentrated on finding abstractions that fit the processes we wanted to implement. It may be worth mentioning that in some cases this meant abstractions that have no equivalent in the TUF specification: some of the issues in the legacy implementation look like the result of mapping the TUF specifications [_Detailed client workflow_](https://theupdateframework.github.io/specification/latest/#detailed-client-workflow) directly into code.

Here are the core abstractions we ended up with (number of lines of code in parenthesis to provide a bit of context, alongside links to sources and docs):
* `Metadata` (900 SLOC, [docs](https://theupdateframework.readthedocs.io/en/latest/api/tuf.api.html)) handles everything related to individual pieces of TUF metadata: deserialization, signing, and verifying
* `TrustedMetadataSet` (170 SLOC) is a collection of local, trusted metadata. It defines rules for how new metadata can be added into the set and ensures that metadata in it is always consistent and valid: As an example, if `TrustedMetadataSet` contains a targets metadata, the set guarantees that the targets metadata is signed by trusted keys and is part of a currently valid TUF snapshot
* `Updater` (250 SLOC, [docs](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.updater.html)) makes decisions on what metadata should be loaded into `TrustedMetadataSet`, both from the local cache and from a remote repository. While `TrustedMetadataSet` always raises an exception if a metadata is not valid, `Updater` considers the context and handles some failures as a part of the process and some as actual errors. `Updater` also handles persisting validated metadata and targets onto local storage and provides the user-facing API
* `FetcherInterface` (100 SLOC, [docs](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.fetcher.html)) is the abstract file downloader. By default, a Requests-based implementation is used but clients can use custom fetchers to tweak how downloads are done

No design is perfect but so far we're quite happy with the above split. It has dramatically simplified the implementation: The code is subjectively easier to understand but also has significantly lower code branching counts for the same operations.

# PyPI client requirements

A year ago we added TUF support into pip as a prototype: this revealed some design issues that made the integration more difficult than it needed to be. As the potential pip integration is a goal for Python-TUF we wanted to smooth those rough edges.

The main addition here was the `FetcherInterface`: it allows pip to keep doing all of the HTTP tweaks they have collected over the years.

There were a bunch of smaller API tweaks as well: as an example, legacy Python-TUF had not anticipated downloading target files from a different host than it downloads metadata from. This is the design that PyPI uses with pypi.org and files.pythonhosted.org.

# better API

Since we knew we had to break API with the legacy implementation anyway, we also fixed multiple paper cuts in the API:
 * Actual data structures are now exposed instead of dictionary "blobs"
 * Configuration was removed or made non-global
 * Exceptions are defined in a way that is useful to client applications
 
# Plain old software engineering

In addition to the big-ticket items, the rewrite allowed loads of improvements in project engineering practices. Some highlights:
* Type annotations are now used extensively
* Coding style is now consistent (and is now a common Python style)
* There is a healthy culture of review in the project: bar for accepting changes is where it should be for a security project
* Testing has so many improvements they probably need a blog post of their own

These are not `ngclient` features as such but we expect they will show in the quality of products built with it.

