# Changelog

## v0.17.0
**NOTE**: this will be the final release of tuf that supports Python 2.7.
This is because Python 2.7 was marked [end-of-life](
https://www.python.org/dev/peps/pep-0373/) in January of 2020, and
since then several of tuf's direct and transient dependencies have stopped
supporting Python 2.7.

### Added
* Added Architectural Decisions Records (ADRs) for:
  * where to develop python-tuf 1.0 (#1220)
  * to justify the extent of OOP in the metadata model (#1229)
  * to decide on a Python code style guide (#1232)

### Changed
* Switch to GitHub Actions for CI (#1242, #1283, #1252)
* Switch to only running bandit on Python versions greater than 3.5 (#1234)
* Bump dependencies: requests (#1245), chardet (#1239), urllib3 (#1268),
  cffi (#1280), securesystemslib (#1285), cryptography (#1282, #1286).
  **NOTE**: the latest version of cryptography is no longer used on
  Python 2, as that is not supported.
* Moved from dependabot-preview to GitHub native Dependabot (#1258)
* Configure dependabot to ignore idna, as it breaks Python 2.7 builds (#1259)
* Install securesystemslib in tox in non-editable mode (#1228)
* Change the editable venv installation order (#1271)

### Fixed
* Updated expiration check in Updater to better match the specification (#1235)
* Ensure tempfile's are closed in Updater (#1226)

### Removed
* Dropped support for Python 3.5 (#1238)

## v0.16.0
### Added
* Begin to document architectural and project-wide decisions as Architectural
  Decision Records (ADRs) in docs/adr (#1182, #1203)
* Add Python 3.9 to the CI test matrix (#1200)
* Implement a class for Root metadata in the simple TUF role metadata model in
  `tuf.api` (#1193)

### Changed
* Bump dependencies: cryptography (#1189, #1190), requests (#1210),
  urllib (#1212), cffi (#1222), certifi (#1201), securesystemslib (#1191)
* Simplify the test runner (`aggregate_tests`) and stop executing unit test
  modules in a random order (#1187)
* Speed up indefinite freeze tests by removing `sleep()` calls (#1194)
* Adapt to securesystemslib changes in key generation interfaces (#1191)
* Migrate from travis-ci.org to travis-ci.com (#1208)
* Make metadata signatures ordered by keyid, to ensure deterministic signature
  ordering in metadata files (#1217)
* Improve test reliability by using thread-safe `Queue`s, rather than files,
  for process communication (#1198)
* Avoid reading an entire target file into memory when generating target file
  hashes in `tuf.client.updater` (#1219)
* Remove use of an empty list (`[]`) as the default argument in a test
  function (#1216)
* Simplified updater logic for downloading and verifying target files (#1202)

### Fixed
* Fix threshold computation in `_verify_root_self_signed()` such that
  signatures by the same root key count only once towards the threshold (#1218)

## v0.15.0
### Added
* Simple TUF role metadata model in the `tuf.api` package for interacting with
  metadata files directly, per-file without the overheads of reading and
  writing the entire repository at once (#1112, #1177, #1183)
* Raise `MissingLocalRepositoryError` in updater when local repository can not
  be found (#1173)
* Tests for targets metadata generation with existing `fileinfo` (#1078)
* Test-verbosity documentation (#1151)

### Changed
* Raise an error in `tuf.client.updater` when metadata is loaded without a
  signature (#1100)
* Print a warning in `tuf.repository_tool` when metadata is written without a
  signature (#1100)
* Remove iso8661 dependency (#1176)
* Bump dependencies: cffi (#1146), cryptography (#1149), urllib (#1179),
  securesystemslib (#1183)
* Overhauled logging to be less verbose and less alarming, by removing logging
  in the library when an exception is raised (including the same information
  that was logged) and using more appropriate log levels (#1145)
* Make test output more useful by reducing and improving logging (#1145, #1104, #1170)
* Make the `targets_path`, `metadata_path` and `confined_target_dirs` fields in
  `tuf.client.updater`s mirror configuration optional (#1153, #1166)
* Include LICENSE files with source distributions (#1162)
* Update Python version to be used in release instructions (#1163)
* Remove direct use of `colorama` and dependency (#1180)

### Fixed
* Ensure file objects and `requests.Responses` are closed during tests (#1147)
* Auto-test against `securesystemslib` head of development (#1185)
* Fix parameter name in `tuf.repository_lib` error message (#1078)

## v0.14.0
### Added
* Added a mechanism to the Updater to disable the hash prefix for target files
  even when `consistent_snapshot` is enabled for a repository (#1102)

### Changed
* Updater now uses keyids provided in the metadata, rather than re-calculating
  keyids using `keyid_hash_algorithms` (#1014, #1121)
* When loading an existing repository the keyids provided in the metadata will
  be used, rather than re-calculating keyids using `keyid_hash_algorithms` (#1014, #1121)
* Improve reliability and performance of tests by removing sleep calls, instead
  use polling to check whether the simple_server is ready to accept
  connections (#1096)
* Only calculate lengths and hashes of files listed by timestamp and snapshot
  metadata when those lengths and hashes will be included in the metadata (#1097)
* Re-raise chained exceptions explicitly per PEP 3134 (#1116)
* Remove use of `securesystemslib.settings.HASH_ALGORITHMS`, instead pass
  desired algorithms explicitly to securesystemslib's
  `keys.format_metadata_to_key` (#1016)

### Fixed
* Better adhere to the detailed client workflow in the specification by
  ensuring that a newly downloaded root metadata file is verified with a
  threshold of its own signatures (#1101)
* Update a delegating role's metadata when adding a new verification key to a
  delegated role (#1037)

## v0.13.0
### Added
* Add support for BLAKE hash functions (#993)
* Don't list root metadata in snapshot metadata, per latest spec (#988)
* Enable targets metadata to be generated without access to the target files (#1007, #1020)
* Implement support for abstract files and directories (#1024, #1034)
* Make lengths and hashes optional for timestamp and snapshot roles (#1031)

### Changed
* Revise requirements files to have layered requirements (#978, #982)
* Update tutorial instructions (#981, #992) and documentation (#1054, #1001)
* Replace hard-coded logger names (#989)
* Fix target file path hashing to ensure paths are hashed as they appear in targets metadata (#1007)
* Refactor code handling hashed bins (#1007, #1013, #1040, #1058)
* Improve performance when delegating to a large number of hashed bins (#1012)
* Improve path handling consistency when adding targets and paths (#1008)
* Clarify error message and docstring for custom parameter of add_target() (#1027)
* Ensure each key applies to signature threshold only once (#1091)

### Fixed
* Fix broken CI (#985)
* Fix tests (#1029, #1064, #1067)
* Fix loading of delegated targets during repository load (#1049, #1052, #1071)
* Fix key loading in repo.py (#1066)
* Remove redundant code in downloader (#1073)
* Fix alarming logging in updater (#1092)

## v0.12.2
* Fix incorrect threshold signature computation (#974)
* Drop support for python 3.4 (#966)
* Improve documentation (#970, #960, #962, #961, 972)
* Improve test suite and tutorial scripts (#775)

## v0.12.1
* Relax spec version format check for backwards compatibility (#950)
* Update project metadata (#937, #939, #944, #947, #948, #953, #954)
* Update misc dependencies (#936, #941, #942, #945, #956)

## v0.12.0
* Add backwards incompatible TUF spec version checks (#842, #844, #854, #914)
* Adopt securesystemslib v0.12.0 update (#909, #910, #855, #912, #934)
* Fix multi-root rotation (#885, #930)
* Fix duplicate schema definitions (#929)
* Refactor metadata generation (#836)
* Refactor securesystemslib interface (#919)
* Update implementation roadmap (#833)
* Improve tests and testing infrastructure (#825, #839, #890, #915, #892, #923)
* Improve documentation (#824, #849, #852, #853, #893, #924, #928, et al.)
* Update misc dependencies (#850, #851, #916, #922, #926, #931)

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

* Support TAP 4 (multiple repository consensus on entrusted targets).
  https://github.com/theupdateframework/taps/blob/master/tap4.md

* Add quick start guide.

* Add CLI (repo.py) to create and modify repositories.

* Refactor client CLI (client.py).

* Add pyup.io to manage dependencies.

* Update all dependencies to their latest versions.

* Add Pylint and Bandit (security) linters to Travis CI.  Fix issues reported
  by both linters.

* Tidy up documentation and directory structure.

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

