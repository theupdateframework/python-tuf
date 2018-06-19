# Changelog

## v0.11.1

* Prevent persistent freeze attack (pr [#737](https://github.com/theupdateframework/tuf/pull/737)).

* Add --no-release option to CLI.

* Issue deprecation warning for all_targets() and targets_of_role().

* Disable file logging, by default.

* Tweak network settings (in settings.py) for production environments.

* Add tuf.log.enable_file_logging() and tuf.log.disable_file_logging().

* Replace %xx escapes in URLs.

* Support Appveyor (for Windows) with Continuous Integration.

* Run unit tests in Python 3.4 & 3.5 under Appveyor.

* Edit contact text to encourage users to report issues with specification.

* Generate (w/ CLI) Ed25519 keys, by default.

* Upgrade dependencies to latest versions.

* Add requirements.in, which is used to generate the other requirement files.

* Update list of adopters.

* Convert README to Markdown.

* Update installation instructions to note SSLib's optional dependencies
  that should be installed to support RSA, ECDSA, etc. keys.

* Add unit test for persistent freeze attack.

* Update list of tasks in ROADMAP.md.

## v0.11.0

Note: This is a backwards-incompatible pre-release.

* Make significant improvements to execution speed of updater.

* Resolve all of the unit test failures in Windows.

* Add or revise many CLI options.
  - Add --revoke
  - Support ECDSA, RSA, and Ed25519 keys
  - Fully support delegated roles
  - Revise help descriptions
  - Allow 2+ roles to delegate to the same role
  - Add --remove
  - Add --trust
  - Remove obsolete code
  - Add --distrust
  - Allow any top-level role to be signed
  - Allow multiple signing keys with --sign
  - Rename default directories
  - etc.

* Revise CLI documentation, such as QUICKSTART.md.

* Ensure consistent behavior between add_targets and add_target().

* Add a CLI doc that demonstrates more complex examples.

* Move LICENSE files to the root directory.

* Update dependencies.

* Update TUTORIAL.md to fix links.

* Fix bug where the latest consistent metadata is not loaded.

* Modify the pyup update schedule from daily to weekly.

* Add hashes to requirements.txt.

* Update AUTHORS.txt and add organizations.

* Replace deprecated 'cryptography' functions.

* Remove dependency in dev-requirements.txt that causes error.

* Ensure that the latest consistent metadata is added to Snapshot.

* Tweak a few logger and exception messages.

* Revise introductory text in README.

* Update ADOPTERS.md and link to pages that cover each adoption.

* Remove target paths in metadata that contain leading path separators.

* Address Pylint/Bandit warnings for the CLI modules.

* Replace calls to deprecated 'imp' module.

* Fix bug where the hashing algorithms used to generate local KEYIDs does not
  match the ones chosen by the repo.

* Fix bug in tuf.sig.get_signature_status() where a given threshold is not used.

* Refactor code that stores the previous keyids of a role.

## v0.10.2

Note: This is a backwards-incompatible pre-release.

* Support TAP 4 (multiple repository concensus on entrusted targets).
  https://github.com/theupdateframework/taps/blob/master/tap4.md

* Add quick start guide.

* Add CLI (repo.py) to create and modify repositories.

* Refactor client CLI (client.py).

* Add pyup.io to manage dependencies.

* Update all dependencies to their latest versions.

* Add Pylint and Bandit (security) linters to Travis CI.  Fix issues reported
  by both linters.

* Tidy up documenation and directory structure.

* Add option to exclude custom field when returning valid targetinfo with
  MultiRepoUpdater.get_valid_targetinfo().

* Fix PGP key fingerprint provided for security vulnerability reports.

* Modify API for creating delegations.

* Add wrapper functions for securesystemslib functions.

* Fix bug: non-default repository names raises an exception.

* Refactor modules for inconsistent use of whitespace and indentation.

* Add cryptographic functions to read and write keys from memory.

* Add full support for ECDSA keys.  List `ecdsa-sha2-nistp256` in specification.

* Remove example metadata.  Documentation now points to up-to-date metadata
  in the tests directory.

* Remove all references to PyCrypto.

* Add copyright and license to all modules.

* Add README for the unit tests.

* Remove remnants of the compressed metadata feature (now discontinued).

* Fix minor issues such as broken links, typos, etc.

* Update configuration files to fix issues, such as duplicate upgrade commands,
  badges, etc.

* Revise policy on static code analysis, CI, etc.

* Earn CII Best Practices Badge.

* Reach 98% score for CII Silver Badge.

* Remove obsolete code, such as tufcli.py, interposition,
  check_crypto_libraries(), etc.


## v0.10.1

Note: This is a backwards-incompatible pre-release.

* Add CHANGELOG.md, MAINTAINERS.txt, CODE-OF-CONDUCT.md, GOVERNANCE.md,
  ADOPTERS.md, DCO requirements, and instructions for submitting a vulnerability
  report.

* Move specification to github.com/theupdateframework/specification.

* Dual license the project: MIT license and Apache license, version 2.

* Update to latest version of securesystemslib v0.10.8, which dropped PyCrypto
  and multi-lib support.

* Add ecdsa-sha2-nistp256 to specification.

* Remove directory of example metadata.  Documentation now references unit test
  metadata.

* Implement TAP 9 (mandatory metadata signing schemes).
  https://github.com/theupdateframework/taps/blob/master/tap9.md

* Drop support for Python 2.6 and 3.3.

* Support Python 3.6.

* Improve code coverage to 99%.

* Convert specification from text to Markdown format.

* Add MERCURY paper, which covers protection against roleback attacks.

* Implement TAP 6 (include specification version in metadata).

* Implement TAP 10 (remove native support for compressed metadata).

* Support ability to append an externally-generated signature to metadata.

* Remove capitalization from rolenames listed in metadata.

* Add a more detailed client workflow to specification.

* Modify client workflow: A client must now fetch root first.  Intermediate
  versions of Root must also be downloaded and verified by the client.  See
  specification for modified workflow.

* Fix bug with key IDs, where incorrect number of key IDs are detected.

* Minor bug fixes, such as catching correct type and number of exceptions,
  detection of slow retrieval attack, etc.

* Do not list Root's hash and lenth in Snapshot (only its version number).

* Allow user to configure hashing algorithm used to generate hashed bin delegations.

* Fix Markdown errors in SECURITY.md.

* Add fast-forward attack to specification

* Remove simple-settings dependency

* Move crypto-related code to external library (securesystemslib).

* Allow replacement of already listed targets in metadata.  Fix issue #319.

* Add instructions for contributors in README.

* Copy (rather than link) target file to consistent target.  Fix issue #390.

* Rename target() -> get_one_valid_targetinfo().

* Ensure consistent Root is written if consistent snapshot = False.  Fix issue #391.

* repository_tool.status(): Print status of only the top-level roles.

* Document and demonstrate protection against repository attacks.

* Add installation instructions for Fedora-based environments.

* Exclude "private" dict key from metadata.

* "backtrack" attribute renamed to "terminating".

* Fix data loss that might occur during sudden power failure.  Pull requests #365, 367.

* Add repository tool function that can mark roles as dirty.

* Store all delegated roles in one flat directory.

* Support Unix shell-style wildcards for paths listed in metadata.

* Add draft of specification (version 1.0).

* Sleep a short while during download.py while loop to release CPU.

* Support multiple key ID hashing algorithms.

* Prepend version number to filename of consistent metadata.

* Remove updater method: refresh_targets_metadata_chain().

* Add Diplomat paper.  It covers integrating TUF with community repositories.

* Add project logo.

* Delegations now resemble a graph, rather than a tree.


## v0.10.0
@vladimir-v-diaz vladimir-v-diaz released this on Jan 22, 2016 · 879 commits to develop since this release

* Fix Python 3 str<->bytes issues

* Drop support for Python 3.2

* Support Python 3.5

* Fix for Issue #244 (hash, rather than hash algorithm, should be prepended to
consistent targets)

## TUF v0.9.9
@vladimir-v-diaz vladimir-v-diaz released this on Jul 23, 2014 · 1058 commits to develop since this release

* Support externally created PEM files. Previous release generated an
unexpected keyid for the external public key because of trailing whitespace,
which did not match the format of internally generated keys saved to metadata.

* Fix installation instructions. Non-wheel installation instruction listed an
invalid command-line option to pip (-no-use-wheel, which is missing a leading
hyphen.)

* Add paragraph to Using TUF section of the README.

## TUF v0.9.8
@vladimir-v-diaz vladimir-v-diaz released this on Jul 16, 2014 · 1069 commits to develop since this release

* TUF 0.9.8 (pre-release)

## TUF v0.7.5

@trishankkkarthik trishankkarthik released this on Sep 21, 2013 · 1877 commits to develop since this release

* TUF 0.7.5 (pre-release)

