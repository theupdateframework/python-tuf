# Changelog

## v1.0.0

This release makes ngclient and the Metadata API the supported python-tuf APIs.
It also removes the legacy implementation as documented in the
[1.0.0 announcement](1.0.0-ANNOUNCEMENT.md): all library code is now contained
in `tuf.api` or `tuf.ngclient`.

### Added
* tests: Extend testing (#1689, #1703, #1711, #1728, #1735, #1738,
  #1742, #1766, #1777, #1809, #1831)

### Changed
* Metadata API: Disallow microseconds in expiry (#1712)
* Metadata API: Preserve role keyid order (#1754)
* Metadata API: Make exceptions more consistent (#1725, #1734, #1787, #1840,
  #1836)
* Metadata API: Update supported spec version to "1.0.28" (#1825)
* Metadata API: Accept legacy spec version "1.0" (#1796)
* Metadata API: Accept custom fields in Metadata (#1861)
* ngclient: Remove temporary file in failure cases (#1757)
* ngclient: Explicitly encode rolename in URL (#1759)
* ngclient: Allow HTTP payload compression (#1774)
* ngclient: Make exceptions more consistent (#1799, #1810)
* docs: Improve documentation (#1744, #1749, #1750, #1755, #1771, #1776, #1772,
  #1780, #1781, #1800, #1815, #1820, #1829, #1838, #1850, #1853, #1855, #1856
  #1868, #1871)
* build: Various build infrastructure improvements (#1718, #1724, #1760, #1762,
  #1767, #1803, #1830, #1832, #1837, #1839)
* build: Stop supporting EOL Python 3.6 (#1783)
* build: Update dependencies (#1809, #1827, #1834, #1863, #1865, #1870)

### Removed
* Remove all legacy code including old client, repository_tool, repository_lib
  and the scripts (#1790)
* Metadata API: Remove modification helper methods that are no longer necessary
  (#1736, #1740, #1743)
* tests: Remove client tests that were replaced with better ones (#1741)
* tests: Stop using unittest_toolbox (#1792)
* docs: Remove deprecated documentation (#1768, #1769, #1773, #1848)


## v0.20.0

*__NOTE:__ This will be the final release of python-tuf that includes the
legacy implementation code. Please see the [*1.0.0
announcement*](1.0.0-ANNOUNCEMENT.md) page for more details about the next
release and the deprecation of the legacy implementation, including migration
instructions.*

### Added
* metadata API: misc input validation (#1630, #1688, #1668, #1672, #1690)
* doc: repository library design document and ADR (#1693)
* doc: 1.0.0 announcement (#1706)
* doc: misc docstrings in metadata API (#1620)
* doc: repository and client examples (#1675, #1685, #1700)
* test: ngclient key rotation (#1635, #1649, #1691)
* test: ngclient top-level role update (#1636)
* test: ngclient non-consistent snapshot (#1666, #1705)
* test: more lint/type checks and auto-formatting (#1658, #1664, #1659, #1674,
        #1677, #1687, #1699, #1701, #1708, #1710, #1720, #1726)
* build: Python 3.10 support (#1628)

### Changed
* ngclient: misc API changes (#1604, #1731)
* ngclient: avoid re-loading verified targets metadata (#1593)
* ngclient: implicitly call refresh() (#1654)
* ngclient: return loaded metadata (#1680)
* ngclient: skip visited nodes on delegation tree traversal (#1683)
* ngclient: remove URL normalisation (#1686)
* build: modernise packaging configuration (#1626)
* build: bump dependencies (#1609, #1611, #1616, #1621)
* build: limit GitHub Action token visibility and permissions (#1652, #1663)
* test: misc test changes (#1715, #1670, #1671, #1631, #1695, #1702)

### Removed
* doc: obsolete roadmap (#1698)

## v0.19.0

For users of legacy client (tuf.client module) this is purely a security fix
release with no API or functionality changes. For ngclient (tuf.ngclient) and
Metadata API (tuf.api.metadata), some API changes are included.

**All users are advised to upgrade**.

Note that python-tuf has required python>=3.5 since release 0.18.0.

### Fixed
* GHSA-wjw6-2cqr-j4qr: Fix client side issue in both legacy client (tuf.client)
  and ngclient (tuf.ngclient) where a malicious repository could trick client
  to overwrite files outside the client metadata store during a metadata
  update. The fix includes percent-encoding the metadata rolename before using
  it as part of a filename
  https://github.com/theupdateframework/python-tuf/security/advisories/GHSA-wjw6-2cqr-j4qr
* ngclient: Do not use urljoin to form metadata URL (included in
  GHSA-wjw6-2cqr-j4qr)
* ngclient: Persist metadata safely (#1574)
* ngclient: Handle timeout on session.get() (#1588)

### Added
* build: Dependabot now monitors GitHub Actions (#1572)
* tests: ngclient test improvements (#1564, #1569, #1587)
* Metadata API: Add TargetFile.from_file() (#1521)

### Changed
* build: Bump dependency charset-normalizer (#1581, #1586)
* build: Bump dependency urllib3 (#1589)
* build: Bump dependency cryptography (#1596)
* Metadata API: Documentation improvements (#1533, #1590)
* Metadata API: change Timestamp meta API  (#1446)
* Metadata API: change Delegations roles API (#1537)
* ngclient: Remove unnecessary sleep() (#1608)
* ngclient: Fix consistent targets URL resolution (#1591)
* ngclient: Don't use target path as local path (#1592)

## v0.18.1

### Changed
* Update setup.cfg to not build universal wheels (#1566)

## v0.18.0

0.18 is a big release with 3 main themes:
* Support only Python 3 and modernize the infrastructure accordingly
* Metadata API (a low-level API for metadata de/serialization and
  modification) is now feature-complete for the client use cases
* ngclient (a new high-level client API) was added. ngclient should be
  considered an unstable API and is not yet recommended for production
  use.

Additionally the Github project name changed: project is now "python-tuf"
instead of "tuf". Redirects are in place for the old name but updating links is
advised.

### Added
* Add ADR6: Where to implement serialization (#1270)
* Add ADR8: Unrecognized fields (#1343)
* Add ADR9: Refine reference implementation purpose (#1554)
* Add client Network IO abstraction (#1250, #1302)
* Add many features to Metadata API to support de/serializing
  specification-compliant metadata, and safer access through API:
  * Metadata.from_bytes()/to_bytes() (#1354, #1490)
  * Key, Role (#1360, #1386, #1423, #1480, #1481, #1520)
  * DelegationRole, Delegations (#1370, #1512)
  * MetaFile, TargetFile (#1329, #1437, #1454, #1514)
  * verification of threshold of signatures (#1435, #1436)
  * expiration check method (#1347)
  * support unrecognized fields in metadata (#1345)
  * use Generics to improve static typing (#1457)
* Extensive Metadata API testing and validation
  (#1359, #1416, #1416, #1430, #1449, #1450, #1451, #1460, #1466, #1511)
* Add ngclient: a new client library implementation
  (#1408, #1448, #1463 #1467, #1470, #1474, #1501, #1509, #1519, #1524)
* Infrastructure improvements:
  * mypy, black and isort integration (#1314, #1363, #1395, #1455, #1489)
  * API reference documentation build (#1517)

### Removed
* Remove Python 2 support (#1293)
* Remove direct dependency on six
* Remove obsolete reference to Thandy in a LICENSE file (#1472)

### Changed
* Bump dependencies:
  * Certifi
  * Cryptography
  * Idna
  * Requests
  * Securesystemslib
  * Six
  * Urllib3
* Replace indirect dependency chardet with charset-normalizer
* Move Metadata API serialization to sub-package (#1279)
* Use SecureSystemslib Signer interface in Metadata API (#1272)
* Make imports compatible with vendoring (#1261)

### Fixed
* 'ecdsa' is a supported key type (#1453)
* Fix various build infrastructure issues (#1289, #1295, #1321, #1327, #1364,
  #1369, #1542)
* Test fixes (#1337, #1346)

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

* Prevent persistent freeze attack (pr [#737](https://github.com/theupdateframework/python-tuf/pull/737)).

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

