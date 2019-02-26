# ROADMAP

This is the roadmap for the project.

## Release schedule
A new release of the project is expected every 3 months.  The release cycle,
upcoming tasks, and any stated goals are subject to change.

Releases are available both on [GitHub](https://github.com/theupdateframework/tuf/releases)
and on [PyPI](https://pypi.org/project/tuf/#history).  The GitHub listing
includes release notes.


## Latest release
Please consult the repository's
[releases page on GitHub](https://github.com/theupdateframework/tuf/releases)
for information about the latest releases.

As of the last editing of this document, the latest release was:
Pre-release v0.11.2.dev3, January 10, 2019.
* [Release notes and Download](https://github.com/theupdateframework/tuf/releases/tag/v0.11.1)
* [PyPI release](https://pypi.org/project/tuf/)
* Packaged by Sebastien Awwad <sebastien.awwad@gmail.com, @awwad>
* PGP fingerprint: C2FB 9C91 0758 B682 7BC4  3233 BC0C 6DED D5E5 CC03

A number of older releases were packaged by Vladimir V Diaz:
* Vladimir Diaz <vladimir.v.diaz@gmail.com, @vladimir-v-diaz>
* PGP fingerprint: 3E87 BB33 9378 BC7B 3DD0  E5B2 5DEE 9B97 B0E2 289A


## Tasks for upcoming releases

In no particular order...

- [ ] Provide protection against a class of slow retrieval attacks using long
inter-byte delays, without sacrificing the use of clean, modern,
production-quality HTTP libraries (requests currently).

- [ ] Support ASN.1 metadata: loading, writing, signing, and verification.

- [x] [CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/1351) badge.
  - [x] silver badge
  - [ ] gold badge (currently at 74%)

- [ ] [Support graph of delegations](https://github.com/theupdateframework/tuf/issues/660)
(requires refactor of API and client code).

- [ ] [TAP 3: Multi-role delegations](https://github.com/theupdateframework/taps/blob/master/tap3.md).

- [x] [TAP 4: Multiple repository consensus on entrusted targets](https://github.com/theupdateframework/taps/blob/master/tap4.md).

- [ ] [TAP 5: Setting URLs for roles in the Root metadata file](https://github.com/theupdateframework/taps/blob/master/tap5.md).

- [ ] [TAP 8: Key rotation and explicit self-revocation](https://github.com/theupdateframework/taps/blob/master/tap8.md).

- [x] CLI tool and quickstart guide.

- [x] Improve update speed.

- [x] Fully support Windows.

- [ ] Generalize metadata format in specification.

- [ ] Support post quantum resilient crypto.

- [ ] Resolve TODOs in the code.

- [ ] Support Python's multilingual internationalization and localization
services.

- [ ] Improved regression and attack testing.

- [ ] Automated tutorial and instructions testing to enforce doc maintenance.

- [ ] Continue resolution of outstanding tickets on the issue tracker.

- [ ] Generalize encrypted key files.  Allow different forms of encryption, key derivation functions, etc.

- [ ] Speed up loading and saving of metadata.  Support option to save metadata to memory.

