# <p align="center">The Update Framework Specification

Last modified: **11 October 2017**

Version: **1.0 (Draft)**

## Table of Contents ##
- [Introduction](#1-introduction)
- [System Overview](#2-system-overview)
- [The Repository](#3-the-repository)
- [Document Formats](#4-document-formats)
- [Detailed Workflows](#5-detailed-workflows)
- [Usage](#6-usage)
- [Consistent Snapshots](#7-consistent-snapshots)
- [Future Directions and Open Questions](#f-future-directions-and-open-questions)

## **1. Introduction**
* **1.1. Scope**

   This document describes a framework for securing software update systems.

   The keywords "MUST," "MUST NOT," "REQUIRED," "SHALL," "SHALL NOT," "SHOULD,"
   "SHOULD NOT," "RECOMMENDED," "MAY," and "OPTIONAL" in this document are to be
   interpreted as described in RFC 2119.

* **1.2. Motivation**

   Software is commonly updated through software update systems.  These systems
   can be package managers that are responsible for all of the software that is
   installed on a system, application updaters that are only responsible for
   individual installed applications, or software library managers that install
   software that adds functionality such as plugins or programming language
   libraries.

   Software update systems all have the common behavior of downloading files
   that identify whether updates exist and, when updates do exist, downloading
   the files that are required for the update.  For the implementations
   concerned with security, various integrity and authenticity checks are
   performed on downloaded files.

   Software update systems are vulnerable to a variety of known attacks.  This
   is generally true even for implementations that have tried to be secure.

* **1.3. History and credit**

   Work on TUF began in late 2009.  The core ideas are based off of previous
   work done by Justin Cappos and Justin Samuel that identified security flaws
   in all popular Linux package managers.  More information and current
   versions of this document can be found at https://www.updateframework.com/

   The [Global Environment for Network Innovations](https://www.geni.net/) (GENI)
   and the [National Science Foundation](https://www.nsf.gov/) (NSF) have
   provided support for the development of TUF.

   TUF's reference implementation is based heavily on
   [Thandy](https://www.torproject.org/), the application
   updater for Tor. Its design and this spec are
   also largely based on Thandy's, with many parts being directly borrowed
   from Thandy. The Thandy spec can be found at
   https://gitweb.torproject.org/thandy.git/tree/specs/thandy-spec.txt

   Whereas Thandy is an application updater for an individual software project,
   TUF aims to provide a way to secure any software update system. We're very
   grateful to the Tor Project and the Thandy developers as it is doubtful our
   design and implementation would have been anywhere near as good without
   being able to use their great work as a starting point. Thandy is the hard
   work of Nick Mathewson, Sebastian Hahn, Roger Dingledine, Martin Peck, and
   others.

 * **1.4. Non-goals**

   We are not creating a universal update system, but rather a simple and
   flexible way that applications can have high levels of security with their
   software update systems.  Creating a universal software update system would
   not be a reasonable goal due to the diversity of application-specific
   functionality in software update systems and the limited usefulness that
   such a system would have for securing legacy software update systems.

   We won't be defining package formats or even performing the actual update
   of application files.  We will provide the simplest mechanism possible that
   remains easy to use and provides a secure way for applications to obtain and
   verify files being distributed by trusted parties.

   We are not providing a means to bootstrap security so that arbitrary
   installation of new software is secure.  In practice this means that people
   still need to use other means to verify the integrity and authenticity of
   files they download manually.

   The framework will not have the responsibility of deciding on the correct
   course of action in all error situations, such as those that can occur when
   certain attacks are being performed.  Instead, the framework will provide
   the software update system the relevant information about any errors that
   require security decisions which are situation-specific.  How those errors
   are handled is up to the software update system.

* **1.5. Goals**

   We need to provide a framework (a set of libraries, file formats, and
   utilities) that can be used to secure new and existing software update
   systems.

   The framework should enable applications to be secure from all known attacks
   on the software update process.  It is not concerned with exposing
   information about what software is being updating (and thus what software
   the client may be running) or the contents of updates.

   The framework should provide means to minimize the impact of key compromise.
   To do so, it must support roles with multiple keys and threshold/quorum
   trust (with the exception of minimally trusted roles designed to use a
   single key).  The compromise of roles using highly vulnerable keys should
   have minimal impact.  Therefore, online keys (keys which are used in an
   automated fashion) must not be used for any role that clients ultimately
   trust for files they may install.

   The framework must be flexible enough to meet the needs of a wide variety of
   software update systems.

   The framework must be easy to integrate with software update systems.

   - **1.5.1 Goals for implementation**

      + The client side of the framework must be straightforward to implement in any
   programming language and for any platform with the requisite networking and
   crypto support.

      +  The process by which developers push updates to the repository must be
   simple.

      + The framework must be secure to use in environments that lack support for
   SSL (TLS).  This does not exclude the optional use of SSL when available,
   but the framework will be designed without it.

   - **1.5.2. Goals to protect against specific attacks**

      Note: When saying the framework protects against an attack,it means
      the attack will not be successful.  It does not mean that a client will
      always be able to successfully update during an attack.  Fundamentally, an
      attacker positioned to intercept and modify a client's communication will
      always be able to perform a denial of service.  The part we have control
      over is not allowing an inability to update to go unnoticed.

      + **Arbitrary installation attacks.** An attacker installs anything they want on
      the client system. That is, an attacker can provide arbitrary files in
      response to download requests and the files will not be detected as
      illegitimate.

      + **Endless data attacks.**  Attackers should not be able to respond to client
      requests with huge amounts of data (extremely large files) that interfere
      with the client's system.

      + **Extraneous dependencies attacks.**  Attackers should not be able to cause
      clients to download or install software dependencies that are not the
      intended dependencies.

      + **Fast-forward attacks.**  An attacker arbitrarily increases the version numbers
      of project metadata files in the snapshot metadata well beyond the current
      value, thus tricking a software update system into thinking any subsequent
      updates are trying to rollback the package to a previous, out-of-date version.
      In some situations, such as those where there is a maximum possible version
      number, the perpetrator could use a number so high that the system would
      never be able to match it with the one in the snapshot metadata, and thus
      new updates could never be downloaded.

      + **Indefinite freeze attacks.**  Attackers should not be able to respond to
      client requests with the same, outdated metadata without the client being
      aware of the problem.

      + **Malicious mirrors preventing updates.**  Repository mirrors should be unable
      to prevent updates from good mirrors.

      + **Mix-and-match attacks.**  Attackers should not be able to trick clients into
      using a combination of metadata that never existed together on the
      repository at the same time.

      + **Rollback attacks.**  Attackers should not be able to trick clients into
      installing software that is older than that which the client previously knew
      to be available.

      + **Slow retrieval attacks.**  Attackers should not be able to prevent clients
      from being aware of interference with receiving updates by responding to
      client requests so slowly that automated updates never complete.

      + **Vulnerability to key compromises.** An attacker who is able to compromise a
      single key or less than a given threshold of keys can compromise clients.
      This includes relying on a single online key (such as only being protected
      by SSL) or a single offline key (such as most software update systems use to
      sign files).

      + **Wrong software installation.**  An attacker provides a client with a trusted
      file that is not the one the client wanted.

   - **1.5.3. Goals for PKIs**

      * Software update systems using the framework's client code interface should
      never have to directly manage keys.

      * All keys must be easily and safely revocable.  Trusting new keys for a role
      must be easy.

      * For roles where trust delegation is meaningful, a role should be able to
      delegate full or limited trust to another role.

      * The root of trust must not rely on external PKI.  That is, no authority will
      be derived from keys outside of the framework.

## **2. System overview**

   The framework ultimately provides a secure method of obtaining trusted
   files.  To avoid ambiguity, we will refer to the files the framework is used
   to distribute as "target files".  Target files are opaque to the framework.
   Whether target files are packages containing multiple files, single text
   files, or executable binaries is irrelevant to the framework.

   The metadata describing target files is the information necessary to
   securely identify the file and indicate which roles are trusted to provide
   the file.  As providing additional information about
   target files may be important to some software update systems using the
   framework, additional arbitrary information can be provided with any target
   file. This information will be included in signed metadata that describes
   the target files.

   The following are the high-level steps of using the framework from the
   viewpoint of a software update system using the framework.  This is an
   error-free case.

       Polling:
            Periodically, the software update system using the framework
            instructs the framework to check each repository for updates.  If
            the framework reports to the application code that there are
            updates, the application code determines whether it wants to
            download the updated target files.  Only target files that are
            trusted (referenced by properly signed and timely metadata) are
            made available by the framework.

       Fetching:
            For each file that the application wants, it asks the framework to
            download the file.  The framework downloads the file and performs
            security checks to ensure that the downloaded file is exactly what
            is expected according to the signed metadata.  The application code
            is not given access to the file until the security checks have been
            completed.  The application asks the framework to copy the
            downloaded file to a location specified by the application.  At
            this point, the application has securely obtained the target file
            and can do with it whatever it wishes.

* **2.1. Roles and PKI**

   In the discussion of roles that follows, it is important to remember that
   the framework has been designed to allow a large amount of flexibility for
   many different use cases.  For example, it is possible to use the framework
   with a single key that is the only key used in the entire system.  This is
   considered to be insecure but the flexibility is provided in order to meet
   the needs of diverse use cases.

   There are four fundamental top-level roles in the framework:
     - Root role
     - Targets role
     - Snapshot role
     - Timestamp role

   There is also one optional top-level role:
     - Mirrors role

   All roles can use one or more keys and require a threshold of signatures of
   the role's keys in order to trust a given metadata file.

  - **2.1.1. Root Role**

      + The root role delegates trust to specific keys trusted for all other
   top-level roles used in the system.

      + The client-side of the framework must ship with trusted root keys for each
   configured repository.

      + The root role's private keys must be kept very secure and thus should be
   kept offline.  If less than a threshold of Root keys are compromised, the
   repository should revoke trust on the compromised keys.  This can be
   accomplished with a normal rotation of root keys, covered in section 6.1
   (Key management and migration). If a threshold of root keys is compromised,
   the Root keys should be updated out-of-band, however, the threshold should
   be chosen so that this is extremely unlikely.  In the unfortunate event that
   a threshold of keys are compromised, it is safest to assume that attackers
   have installed malware and taken over affected machines.  For this reason,
   making it difficult for attackers to compromise all of the offline keys is
   important because safely recovering from it is nearly impossible.


  - **2.1.2 Targets role**

      The targets role's signature indicates which target files are trusted by
      clients.  The targets role signs metadata that describes these files, not
      the actual target files themselves.

      In addition, the targets role can delegate full or partial trust to other
  roles.  Delegating trust means that the targets role indicates another role
  (that is, another set of keys and the threshold required for trust) is
  trusted to sign target file metadata.  Partial trust delegation is when the
  delegated role is only trusted for some of the target files that the
  delegating role is trusted for.

      Delegated developer roles can further delegate trust to other delegated
  roles.  This provides for multiple levels of trust delegation where each
  role can delegate full or partial trust for the target files they are
  trusted for.  The delegating role in these cases is still trusted.  That is,
  a role does not become untrusted when it has delegated trust.

      Delegated trust can be revoked at any time by the delegating role signing
  new metadata that indicates the delegated role is no longer trusted.

 - **2.1.3 Snapshot role**

   The snapshot role signs a metadata file that provides information about the
   latest version of all of the other metadata on the repository (excluding the
   timestamp file, discussed below).  This information allows clients to know
   which metadata files have been updated and also prevents mix-and-match
   attacks.

 - **2.1.4 Timestamp role**

   To prevent an adversary from replaying an out-of-date signed metadata file
   whose signature has not yet expired, an automated process periodically signs
   a timestamped statement containing the hash of the snapshot file.  Even
   though this timestamp key must be kept online, the risk posed to clients by
   compromise of this key is minimal.

 - **2.1.5 Mirrors role**

   Every repository has one or more mirrors from which files can be downloaded
   by clients.  A software update system using the framework may choose to
   hard-code the mirror information in their software or they may choose to use
   mirror metadata files that can optionally be signed by a mirrors role.

   The importance of using signed mirror lists depends on the application and
   the users of that application.  There is minimal risk to the application's
   security from being tricked into contacting the wrong mirrors.  This is
   because the framework has very little trust in repositories.

* **2.2. Threat Model And Analysis**

   We assume an adversary who can respond to client requests, whether by acting
   as a man-in-the-middle or through compromising repository mirrors.  At
   worst, such an adversary can deny updates to users if no good mirrors are
   accessible.  An inability to obtain updates is noticed by the framework.

   If an adversary compromises enough keys to sign metadata, the best that can
   be done is to limit the number of users who are affected.  The level to
   which this threat is mitigated is dependent on how the application is using
   the framework.  This includes whether different keys have been used for
   different signing roles.

   A detailed threat analysis is outside the scope of this document.  This is
   partly because the specific threat posted to clients in many situations is
   largely determined by how the framework is being used.

## **3. The repository**

   An application uses the framework to interact with one or more repositories.
   A repository is a conceptual source of target files of interest to the
   application.  Each repository has one or more mirrors which are the actual
   providers of files to be downloaded.  For example, each mirror may specify a
   different host where files can be downloaded from over HTTP.

   The mirrors can be full or partial mirrors as long as the application-side
   of the framework can ultimately obtain all of the files it needs.  A mirror
   is a partial mirror if it is missing files that a full mirror should have.
   If a mirror is intended to only act as a partial mirror, the metadata and
   target paths available from that mirror can be specified.

   Roles, trusted keys, and target files are completely separate between
   repositories.  A multi-repository setup is a multi-root system.  When an
   application uses the framework with multiple repositories, the framework
   does not perform any "mixing" of the trusted content from each repository.
   It is up to the application to determine the significance of the same or
   different target files provided from separate repositories.

* **3.1 Repository layout**

   The filesystem layout in the repository is used for two purposes:
     - To give mirrors an easy way to mirror only some of the repository.
     - To specify which parts of the repository a given role has authority
       to sign/provide.

 + **3.1.1 Target files**

   The filenames and the directory structure of target files available from
   a repository are not specified by the framework.  The names of these files
   and directories are completely at the discretion of the application using
   the framework.

 + **3.1.2 Metadata files**

   The filenames and directory structure of repository metadata are strictly
   defined.  The following are the metadata files of top-level roles relative
   to the base URL of metadata available from a given repository mirror.

    /root.json

         Signed by the root keys; specifies trusted keys for the other
         top-level roles.

    /snapshot.json

         Signed by the snapshot role's keys.  Lists the version numbers of all
         metadata files other than timestamp.json.

    /targets.json

         Signed by the target role's keys.  Lists hashes and sizes of target
         files.

    /timestamp.json

         Signed by the timestamp role's keys.  Lists hash(es), size, and version
         number of the snapshot file.  This is the first and potentially only
         file that needs to be downloaded when clients poll for the existence
         of updates.

    /mirrors.json (optional)

         Signed by the mirrors role's keys.  Lists information about available
         mirrors and the content available from each mirror.

  + **3.1.2.1 Metadata files for targets delegation**

   When the targets role delegates trust to other roles, each delegated role
   provides one signed metadata file.  As is the case with the directory
   structure of top-level metadata, the delegated files are relative to the
   base URL of metadata available from a given repository mirror.

   A delegated role file is located at:

    /DELEGATED_ROLE.json

   where DELEGATED_ROLE is the name of the delegated role that has been
   specified in targets.json.  If this role further delegates trust to a role
   named ANOTHER_ROLE, that role's signed metadata file is made available at:

    /ANOTHER_ROLE.json

## **4. Document formats**

   All of the formats described below include the ability to add more
   attribute-value fields for backwards-compatible format changes.  If
   a backwards incompatible format change is needed, a new filename can
   be used.

* **4.1. Metaformat**

   All documents use a subset of the JSON object format, with
   floating-point numbers omitted.  When calculating the digest of an
   object, we use the "canonical JSON" subdialect as described at
        http://wiki.laptop.org/go/Canonical_JSON

* **4.2. File formats: general principles**

   All signed metadata objects have the format:

       { "signed" : ROLE,
         "signatures" : [
            { "keyid" : KEYID,
              "sig" : SIGNATURE }
            , ... ]
       }

   where: ROLE is a dictionary whose "_type" field describes the role type.
          KEYID is the identifier of the key signing the ROLE dictionary.
          SIGNATURE is a signature of the canonical JSON form of ROLE.

   The current reference implementation defines two signature schemes,
   although TUF is not restricted to any particular signature scheme,
   key type, or cryptographic library:

       "rsassa-pss-sha256" : RSA Probabilistic signature scheme with appendix.
          The underlying hash function is SHA256.

       "ed25519" : Elliptic curve digital signature algorithm based on Twisted
          Edwards curves.

        "ecdsa-sha2-nistp256" : Elliptic Curve Digital Signature Algorithm
           with NIST P-256 curve signing and SHA-256 hashing.

   rsassa-pss: https://tools.ietf.org/html/rfc3447#page-29

   ed25519: https://ed25519.cr.yp.to/

   ecdsa: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm

   All keys have the format:

        { "keytype" : KEYTYPE,
          "scheme" : SCHEME,
          "keyval" : KEYVAL
        }

   where KEYTYPE is a string describing the type of the key and how it's
   used to sign documents.  The type determines the interpretation of
   KEYVAL.

   We define three keytypes below: 'rsa', 'ed25519', and 'ecdsa'.  However, TUF
   places no restrictions on cryptographic keys.  Adopters can use any
   particular keytype, signing scheme, and cryptographic library.

   The 'rsa' format is:

        { "keytype" : "rsa",
          "scheme" : "rsassa-pss-sha256",
          "keyval" : { "public" : PUBLIC}
        }

   where PUBLIC is in PEM format and a string.  All RSA keys
   must be at least 2048 bits.

   The 'ed25519' format is:

        { "keytype" : "ed25519",
          "scheme" : "ed25519",
          "keyval" : { "public" : PUBLIC}
        }

   where PUBLIC is a 32-byte string.

   The 'ecdsa' format is:

        { "keytype" : "ecdsa-sha2-nistp256",
          "scheme" : "ecdsa-sha2-nistp256",
          "keyval" : { "public" : PUBLIC}
        }

   where PUBLIC is in PEM format and a string.

   The KEYID of a key is the hexdigest of the SHA-256 hash of the
   canonical JSON form of the key.

   Metadata date-time data follows the ISO 8601 standard.  The expected format
   of the combined date and time string is "YYYY-MM-DDTHH:MM:SSZ".  Time is
   always in UTC, and the "Z" time zone designator is attached to indicate a
   zero UTC offset.  An example date-time string is "1985-10-21T01:21:00Z".


* **4.3. File formats: root.json**

   The root.json file is signed by the root role's keys.  It indicates
   which keys are authorized for all top-level roles, including the root
   role itself.  Revocation and replacement of top-level role keys, including
   for the root role, is done by changing the keys listed for the roles in
   this file.

   The "signed" portion of root.json is as follows:

       { "_type" : "root",
         "spec_version" : SPEC_VERSION,
         "consistent_snapshot": CONSISTENT_SNAPSHOT,
         "version" : VERSION,
         "expires" : EXPIRES,
         "keys" : {
             KEYID : KEY
             , ... },
         "roles" : {
             ROLE : {
               "keyids" : [ KEYID, ... ] ,
               "threshold" : THRESHOLD }
             , ... }
       }

   SPEC_VERSION is the version number of the specification.  Metadata is
   written according to version "spec_version" of the specification, and
   clients MUST verify that "spec_version" matches the expected version number.
   Adopters are free to determine what is considered a match (e.g., the version
   number must exactly exactly, or perhaps only the major version number
   (major.minor.fix).

   CONSISTENT_SNAPSHOT is a boolean indicating whether the repository supports
   consistent snapshots.  Section 7 goes into more detail on the consequences
   of enabling this setting on a repository.

   VERSION is an integer that is greater than 0.  Clients MUST NOT replace a
   metadata file with a version number less than the one currently trusted.

   EXPIRES determines when metadata should be considered expired and no longer
   trusted by clients.  Clients MUST NOT trust an expired file.

   A ROLE is one of "root", "snapshot", "targets", "timestamp", or "mirrors".
   A role for each of "root", "snapshot", "timestamp", and "targets" MUST be
   specified in the key list. The role of "mirror" is optional.  If not
   specified, the mirror list will not need to be signed if mirror lists are
   being used.

   The KEYID must be correct for the specified KEY.  Clients MUST calculate
   each KEYID to verify this is correct for the associated key.  Clients MUST
   ensure that for any KEYID represented in this key list and in other files,
   only one unique key has that KEYID.

   The THRESHOLD for a role is an integer of the number of keys of that role
   whose signatures are required in order to consider a file as being properly
   signed by that role.

   A root.json example file:

       {
       "signatures": [
        {
         "keyid": "f2d5020d08aea06a0a9192eb6a4f549e17032ebefa1aa9ac167c1e3e727930d6",
         "sig": "a312b9c3cb4a1b693e8ebac5ee1ca9cc01f2661c14391917dcb111517f72370809
                 f32c890c6b801e30158ac4efe0d4d87317223077784c7a378834249d048306"
        }
       ],
       "signed": {
        "_type": "root",
        "spec_version": "1",
        "consistent_snapshot": false,
        "expires": "2030-01-01T00:00:00Z",
        "keys": {
         "1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4": {
          "keytype": "ed25519",
          "scheme": "ed25519",
          "keyval": {
           "public": "72378e5bc588793e58f81c8533da64a2e8f1565c1fcc7f253496394ffc52542c"
          }
         },
         "93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b": {
          "keytype": "ed25519",
          "scheme": "ed25519",
          "keyval": {
           "public": "68ead6e54a43f8f36f9717b10669d1ef0ebb38cee6b05317669341309f1069cb"
          }
         },
         "f2d5020d08aea06a0a9192eb6a4f549e17032ebefa1aa9ac167c1e3e727930d6": {
          "keytype": "ed25519",
          "scheme": "ed25519",
          "keyval": {
           "public": "66dd78c5c2a78abc6fc6b267ff1a8017ba0e8bfc853dd97af351949bba021275"
          }
         },
         "fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309": {
          "keytype": "ed25519",
          "scheme": "ed25519",
          "keyval": {
           "public": "01c61f8dc7d77fcef973f4267927541e355e8ceda757e2c402818dad850f856e"
          }
         }
        },
        "roles": {
         "root": {
          "keyids": [
           "f2d5020d08aea06a0a9192eb6a4f549e17032ebefa1aa9ac167c1e3e727930d6"
          ],
          "threshold": 1
         },
         "snapshot": {
          "keyids": [
           "fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309"
          ],
          "threshold": 1
         },
         "targets": {
          "keyids": [
           "93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b"
          ],
          "threshold": 1
         },
         "timestamp": {
          "keyids": [
           "1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4"
          ],
          "threshold": 1
         }
        },
        "version": 1
       }
      }

* **4.4. File formats: snapshot.json**

   The snapshot.json file is signed by the snapshot role.  It lists the version
   numbers of all metadata on the repository, excluding timestamp.json and
   mirrors.json.  For the root role, the hash(es), size, and version number
   are listed.

   The "signed" portion of snapshot.json is as follows:

       { "_type" : "snapshot",
         "spec_version" : SPEC_VERSION,
         "version" : VERSION,
         "expires" : EXPIRES,
         "meta" : METAFILES
       }

   METAFILES is an object whose format is the following:

       { METAPATH : {
             "version" : VERSION }
         , ...
       }

   METAPATH is the the metadata file's path on the repository relative to the
   metadata base URL.

   VERSION is listed for the root file
   and all other roles available on the repository.

   A snapshot.json example file:

       {
       "signatures": [
        {
         "keyid": "fce9cf1cc86b0945d6a042f334026f31ed8e4ee1510218f198e8d3f191d15309",
         "sig": "f7f03b13e3f4a78a23561419fc0dd741a637e49ee671251be9f8f3fceedfc112e4
                 4ee3aaff2278fad9164ab039118d4dc53f22f94900dae9a147aa4d35dcfc0f"
        }
       ],
       "signed": {
        "_type": "snapshot",
        "spec_version": "1",
        "expires": "2030-01-01T00:00:00Z",
        "meta": {
         "root.json": {
          "version": 1
         },
         "targets.json": {
          "version": 1
         },
         "project.json": {
          "version": 1
          },
         }
        "version": 1
        },
       }

* **4.5. File formats: targets.json and delegated target roles**

   The "signed" portion of targets.json is as follows:

       { "_type" : "targets",
         "spec_version" : SPEC_VERSION,
         "version" : VERSION,
         "expires" : EXPIRES,
         "targets" : TARGETS,
         ("delegations" : DELEGATIONS)
       }

   TARGETS is an object whose format is the following:

       { TARGETPATH : {
             "length" : LENGTH,
             "hashes" : HASHES,
             ("custom" : { ... }) }
         , ...
       }

   Each key of the TARGETS object is a TARGETPATH.  A TARGETPATH is a path to
   a file that is relative to a mirror's base URL of targets.

   It is allowed to have a TARGETS object with no TARGETPATH elements.  This
   can be used to indicate that no target files are available.

   If defined, the elements and values of "custom" will be made available to the
   client application.  The information in "custom" is opaque to the framework
   and can include version numbers, dependencies, requirements, and any other
   data that the application wants to include to describe the file at
   TARGETPATH.  The application may use this information to guide download
   decisions.

   DELEGATIONS is an object whose format is the following:

       { "keys" : {
             KEYID : KEY,
             ... },
         "roles" : [{
             "name": ROLENAME,
             "keyids" : [ KEYID, ... ] ,
             "threshold" : THRESHOLD,
             ("path_hash_prefixes" : [ HEX_DIGEST, ... ] |
              "paths" : [ PATHPATTERN, ... ]),
             "terminating": TERMINATING,
         }, ... ]
       }

   ROLENAME is the name of the delegated role.  For example,
   "projects".

   TERMINATING is a boolean indicating whether subsequent delegations should be
   considered.

   As explained in the [Diplomat
   paper](https://github.com/theupdateframework/tuf/blob/develop/docs/papers/protect-community-repositories-nsdi2016.pdf),
   terminating delegations instruct the client not to consider future trust
   statements that match the delegation's pattern, which stops the delegation
   processing once this delegation (and its descendants) have been processed.
   A terminating delegation for a package causes any further statements about a
   package that are not made by the delegated party or its descendants to be
   ignored.

   In order to discuss target paths, a role MUST specify only one of the
   "path_hash_prefixes" or "paths" attributes, each of which we discuss next.

   The "path_hash_prefixes" list is used to succinctly describe a set of target
   paths. Specifically, each HEX_DIGEST in "path_hash_prefixes" describes a set
   of target paths; therefore, "path_hash_prefixes" is the union over each
   prefix of its set of target paths. The target paths must meet this
   condition: each target path, when hashed with the SHA-256 hash function to
   produce a 64-byte hexadecimal digest (HEX_DIGEST), must share the same
   prefix as one of the prefixes in "path_hash_prefixes". This is useful to
   split a large number of targets into separate bins identified by consistent
   hashing.

   The "paths" list describes paths that the role is trusted to provide.
   Clients MUST check that a target is in one of the trusted paths of all roles
   in a delegation chain, not just in a trusted path of the role that describes
   the target file.  PATHPATTERN can include shell-style wildcards and supports
   the Unix filename pattern matching convention.  Its format may either
   indicate a path to a single file, or to multiple paths with the use of
   shell-style wildcards.  For example, the path pattern "targets/*.tgz" would
   match file paths "targets/foo.tgz" and "targets/bar.tgz", but not
   "targets/foo.txt".  Likewise, path pattern "foo-version-?.tgz" matches
   foo-version-2.tgz" and "foo-version-a.tgz", but not "foo-version-alpha.tgz".

   Prioritized delegations allow clients to resolve conflicts between delegated
   roles that share responsibility for overlapping target paths.  To resolve
   conflicts, clients must consider metadata in order of appearance of delegations;
   we treat the order of delegations such that the first delegation is trusted
   over the second one, the second delegation is trusted more than the third
   one, and so on. Likewise, the metadata of the first delegation will override that
   of the second delegation, the metadata of the second delegation will override
   that of the third one, etc. In order to accommodate prioritized
   delegations, the "roles" key in the DELEGATIONS object above points to an array
   of delegated roles, rather than to a hash table.

   The metadata files for delegated target roles has the same format as the
   top-level targets.json metadata file.

   A targets.json example file:

       {
       "signatures": [
        {
         "keyid": "93ec2c3dec7cc08922179320ccd8c346234bf7f21705268b93e990d5273a2a3b",
         "sig": "e9fd40008fba263758a3ff1dc59f93e42a4910a282749af915fbbea1401178e5a0
                 12090c228f06db1deb75ad8ddd7e40635ac51d4b04301fce0fd720074e0209"
        }
       ],
       "signed": {
        "_type": "targets",
        "spec_version": "1",
        "delegations": {
         "keys": {
          "ce3e02e72980b09ca6f5efa68197130b381921e5d0675e2e0c8f3c47e0626bba": {
           "keytype": "ed25519",
           "scheme": "ed25519",
           "keyval": {
            "public": "b6e40fb71a6041212a3d84331336ecaa1f48a0c523f80ccc762a034c727606fa"
           }
          }
         },
         "roles": [
          {
           "keyids": [
            "ce3e02e72980b09ca6f5efa68197130b381921e5d0675e2e0c8f3c47e0626bba"
           ],
           "name": "project",
           "paths": [
            "/project/file3.txt"
           ],
           "threshold": 1
          }
         ]
        },
        "expires": "2030-01-01T00:00:00Z",
        "targets": {
         "/file1.txt": {
          "hashes": {
           "sha256": "65b8c67f51c993d898250f40aa57a317d854900b3a04895464313e48785440da"
          },
          "length": 31
         },
         "/file2.txt": {
          "hashes": {
           "sha256": "452ce8308500d83ef44248d8e6062359211992fd837ea9e370e561efb1a4ca99"
          },
          "length": 39
         }
        },
        "version": 1
        }
       }

* **4.6. File formats: timestamp.json**

   The timestamp file is signed by a timestamp key.  It indicates the
   latest versions of other files and is frequently resigned to limit the
   amount of time a client can be kept unaware of interference with obtaining
   updates.

   Timestamp files will potentially be downloaded very frequently.  Unnecessary
   information in them will be avoided.

   The "signed" portion of timestamp.json is as follows:

       { "_type" : "timestamp",
         "spec_version" : SPEC_VERSION,
         "version" : VERSION,
         "expires" : EXPIRES,
         "meta" : METAFILES
       }

   METAFILES is the same is described for the snapshot.json file.  In the case
   of the timestamp.json file, this will commonly only include a description of
   the snapshot.json file.

   A signed timestamp.json example file:

       {
       "signatures": [
        {
         "keyid": "1a2b4110927d4cba257262f614896179ff85ca1f1353a41b5224ac474ca71cb4",
         "sig": "90d2a06c7a6c2a6a93a9f5771eb2e5ce0c93dd580bebc2080d10894623cfd6eaed
                 f4df84891d5aa37ace3ae3736a698e082e12c300dfe5aee92ea33a8f461f02"
        }
       ],
       "signed": {
        "_type": "timestamp",
        "spec_version": "1",
        "expires": "2030-01-01T00:00:00Z",
        "meta": {
         "snapshot.json": {
          "hashes": {
           "sha256": "c14aeb4ac9f4a8fc0d83d12482b9197452f6adf3eb710e3b1e2b79e8d14cb681"
          },
          "length": 1007,
          "version": 1
         }
        },
        "version": 1
        }
       }

* **4.7. File formats: mirrors.json**

   The mirrors.json file is signed by the mirrors role.  It indicates which
   mirrors are active and believed to be mirroring specific parts of the
   repository.

   The "signed" portion of mirrors.json is as follows:


      { "_type" : "mirrors",
       "spec_version" : SPEC_VERSION,
       "version" : VERSION,
       "expires" : EXPIRES,
       "mirrors" : [
          { "urlbase" : URLBASE,
            "metapath" : METAPATH,
            "targetspath" : TARGETSPATH,
            "metacontent" : [ PATHPATTERN ... ] ,
            "targetscontent" : [ PATHPATTERN ... ] ,
            ("custom" : { ... }) }
          , ... ]
      }

   URLBASE is the URL of the mirror which METAPATH and TARGETSPATH are relative
   to.  All metadata files will be retrieved from METAPATH and all target files
   will be retrieved from TARGETSPATH.

   The lists of PATHPATTERN for "metacontent" and "targetscontent" describe the
   metadata files and target files available from the mirror.

   The order of the list of mirrors is important.  For any file to be
   downloaded, whether it is a metadata file or a target file, the framework on
   the client will give priority to the mirrors that are listed first.  That is,
   the first mirror in the list whose "metacontent" or "targetscontent" include
   a path that indicate the desired file can be found there will the first
   mirror that will be used to download that file.  Successive mirrors with
   matching paths will only be tried if downloading from earlier mirrors fails.
   This behavior can be modified by the client code that uses the framework to,
   for example, randomly select from the listed mirrors.

## **5. Detailed Workflows**

* **5.1. The client application**

    0. **Load the trusted root metadata file.** We assume that a good, trusted
    copy of this file was shipped with the package manager / software updater
    using an out-of-band process.

    0.1. Note that the expiration of the trusted root metadata file does not
    matter, because we will attempt to update it in the next step.

    1. **Update the root metadata file.** Since it may now be signed using
    entirely different keys, the client must somehow be able to establish a
    trusted line of continuity to the latest set of keys (see Section 6.1). To
    do so, the client MUST download intermediate root metadata files, until the
    latest available one is reached.

    1.1. Let N denote the version number of the trusted root metadata file.

    1.2. **Try downloading version N+1 of the root metadata file**, up to some
    X number of bytes (because the size is unknown). The value for X is set by
    the authors of the application using TUF. For example, X may be tens of
    kilobytes. The filename used to download the root metadata file is of the
    fixed form VERSION.FILENAME.EXT (e.g., 42.root.json). If this file is not
    available, then go to step 1.8.

    1.3. **Check signatures.** Version N+1 of the root metadata file MUST have
    been signed by: (1) a threshold of keys specified in the trusted root
    metadata file (version N), and (2) a threshold of keys specified in the
    new root metadata file being validated (version N+1).

    1.4. **Check for a rollback attack.** The version number of the trusted
    root metadata file (version N) must be less than or equal to the version
    number of the new root metadata file (version N+1). Effectively, this means
    checking that the version number signed in the new root metadata file is
    indeed N+1.

    1.5. Note that the expiration of the new (intermediate) root metadata
    file does not matter yet, because we will check for it in step 1.8.

    1.6. Set the trusted root metadata file to the new root metadata file.

    1.7. Repeat steps 1.1 to 1.7.

    1.8. **Check for a freeze attack.** The latest known time should be lower
    than the expiration timestamp in the trusted root metadata file.

    1.9. **If the timestamp and / or snapshot keys have been rotated, then
    delete the trusted timestamp and snapshot metadata files.** This is done
    in order to recover from fast-forward attacks after the repository has been
    compromised and recovered. A _fast-forward attack_ happens when attackers
    arbitrarily increase the version numbers of: (1) the timestamp metadata,
    (2) the snapshot metadata, and / or (3) the targets, or a delegated
    targets, metadata file in the snapshot metadata. Please see [the submitted
    Mercury
    draft](https://ssl.engineering.nyu.edu/papers/kuppusamy_usenix_17.pdf) for
    more details.

    2. **Download the timestamp metadata file**, up to Y number of bytes
    (because the size is unknown.) The value for Y is set by the authors of the
    application using TUF. For example, Y may be tens of kilobytes. The
    filename used to download the timestamp metadata file is of the fixed form
    FILENAME.EXT (e.g., timestamp.json).

    2.1. **Check signatures.** The new timestamp metadata file must have been
    signed by a threshold of keys specified in the trusted root metadata file.

    2.2. **Check for a rollback attack.** The version number of the trusted
    timestamp metadata file, if any, must be less than or equal to the version
    number of the new timestamp metadata file.

    2.3. **Check for a freeze attack.** The latest known time should be lower
    than the expiration timestamp in the new timestamp metadata file.  If so,
    the new timestamp metadata file becomes the trusted timestamp
    metadata file.

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

    3.1. **Check against timestamp metadata.** The hashes and version number
    of the new snapshot metadata file MUST match the hashes and version number
    listed in timestamp metadata.

    3.2. **Check signatures.** The snapshot metadata file MUST have been signed
    by a threshold of keys specified in the trusted root metadata file.

    3.3. **Check for a rollback attack.**

    3.3.1. Note that the trusted snapshot metadata file may be checked for
    authenticity, but its expiration does not matter for the following
    purposes.

    3.3.2. The version number of the trusted snapshot metadata file, if any,
    MUST be less than or equal to the version number of the new snapshot
    metadata file.

    3.3.3. The version number of the targets metadata file, and all delegated
    targets metadata files (if any), in the trusted snapshot metadata file, if
    any, MUST be less than or equal to its version number in the new snapshot
    metadata file. Furthermore, any targets metadata filename that was listed
    in the trusted snapshot metadata file, if any, MUST continue to be listed
    in the new snapshot metadata file.

    3.4. **Check for a freeze attack.** The latest known time should be lower
    than the expiration timestamp in the new snapshot metadata file.  If so,
    the new snapshot metadata file becomes the trusted snapshot metadata
    file.

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
    number of the new targets metadata file MUST match the trusted snapshot metadata.
    This is done, in part, to prevent a mix-and-match attack by man-in-the-middle
    attackers.

    4.2. **Check for an arbitrary software attack.** The new targets metadata file
    MUST have been signed by a threshold of keys specified in the trusted root
    metadata file.

    4.3. **Check for a rollback attack.** The version number of the trusted
    targets metadata file, if any, MUST be less than or equal to the version
    number of the new targets metadata file.

    4.4. **Check for a freeze attack.** The latest known time should be lower
    than the expiration timestamp in the new targets metadata file.  If so,
    the new targets metadata file becomes the trusted targets metadata file.

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

    5. Verify the desired target against its targets metadata

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

## **6. Usage**

   See https://www.theupdateframework.com/ for discussion of recommended usage
   in various situations.

* **6.1. Key management and migration**

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

## **7. Consistent Snapshots**

   So far, we have considered a TUF repository that is relatively static (in
   terms of how often metadata and target files are updated). The problem is
   that if the repository (which may be a community repository such as PyPI,
   RubyGems, CPAN, or SourceForge) is volatile, in the sense that the
   repository is continually producing new TUF metadata as well as its targets,
   then should clients read metadata while the same metadata is being written
   to, they would effectively see denial-of-service attacks.  Therefore, the
   repository needs to be careful about how it writes metadata and targets. The
   high-level idea of the solution is that each snapshot will be contained in a
   so-called consistent snapshot. If a client is reading from one consistent
   snapshot, then the repository is free to write another consistent snapshot
   without interrupting that client. For more reasons on why we need consistent
   snapshots, please see
   https://github.com/theupdateframework/pep-on-pypi-with-tuf#why-do-we-need-consistent-snapshots

* **7.1. Writing consistent snapshots**

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

    For more details on how this would apply on a community repository, please
    see https://github.com/theupdateframework/pep-on-pypi-with-tuf#producing-consistent-snapshots

* **7.2. Reading consistent snapshots**

    See Section 5.1 for more details.

## **F. Future directions and open questions**

* **F.1. Support for bogus clocks.**

   The framework may need to offer an application-enablable "no, my clock is
   _supposed_ to be wrong" mode, since others have noticed that many users seem
   to have incorrect clocks.
