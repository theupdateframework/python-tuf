"""
A TUF repository example using the low-level TUF Metadata API.

The example code in this file demonstrates how to *manually* create and
maintain repository metadata using the low-level Metadata API. It implements
similar functionality to that of the deprecated legacy 'repository_tool' and
'repository_lib'. (see ADR-0010 for details about repository library design)

Contents:
 * creation of top-level metadata
 * target file handling
 * consistent snapshots
 * key management
 * top-level delegation and signing thresholds
 * target delegation
 * in-band and out-of-band metadata signing
 * writing and reading metadata files
 * root key rotation

NOTE: Metadata files will be written to a 'tmp*'-directory in CWD.

"""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer


def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        days=days
    )


# Create top-level metadata
# =========================
# Every TUF repository has at least four roles, i.e. the top-level roles
# 'targets', 'snapshot', 'timestamp' and 'root'. Below we will discuss their
# purpose, show how to create the corresponding metadata, and how to use them
# to provide integrity, consistency and freshness for the files TUF aims to
# protect, i.e. target files.

# Common fields
# -------------
# All roles have the same metadata container format, for which the metadata API
# provides a generic 'Metadata' class. This class has two fields, one for
# cryptographic signatures, i.e. 'signatures', and one for the payload over
# which signatures are generated, i.e. 'signed'. The payload must be an
# instance of either 'Targets', 'Snapshot', 'Timestamp' or 'Root' class. Common
# fields in all of these 'Signed' classes are:
#
# spec_version -- The supported TUF specification version number.
# version -- The metadata version number.
# expires -- The metadata expiry date.
#
# The 'version', which is incremented on each metadata change, is used to
# reference metadata from within other metadata, and thus allows for repository
# consistency in addition to protecting against rollback attacks.
#
# The date the metadata 'expires' protects against freeze attacks and allows
# for implicit key revocation. Choosing an appropriate expiration interval
# depends on the volatility of a role and how easy it is to re-sign them.
# Highly volatile roles (timestamp, snapshot, targets), usually have shorter
# expiration intervals, whereas roles that change less and might use offline
# keys (root, delegating targets) may have longer expiration intervals.

SPEC_VERSION = ".".join(SPECIFICATION_VERSION)

# Define containers for role objects and cryptographic keys created below. This
# allows us to sign and write metadata in a batch more easily.
roles: Dict[str, Metadata] = {}
signers: Dict[str, Signer] = {}


# Targets (integrity)
# -------------------
# The targets role guarantees integrity for the files that TUF aims to protect,
# i.e. target files. It does so by listing the relevant target files, along
# with their hash and length.
roles["targets"] = Metadata(Targets(expires=_in(7)))

# For the purpose of this example we use the top-level targets role to protect
# the integrity of this very example script. The metadata entry contains the
# hash and length of this file at the local path. In addition, it specifies the
# 'target path', which a client uses to locate the target file relative to a
# configured mirror base URL.
#
#      |----base artifact URL---||-------target path-------|
# e.g. tuf-examples.org/artifacts/manual_repo/basic_repo.py

local_path = Path(__file__).resolve()
target_path = f"{local_path.parts[-2]}/{local_path.parts[-1]}"

target_file_info = TargetFile.from_file(target_path, str(local_path))
roles["targets"].signed.targets[target_path] = target_file_info

# Snapshot (consistency)
# ----------------------
# The snapshot role guarantees consistency of the entire repository. It does so
# by listing all available targets metadata files at their latest version. This
# becomes relevant, when there are multiple targets metadata files in a
# repository and we want to protect the client against mix-and-match attacks.
roles["snapshot"] = Metadata(Snapshot(expires=_in(7)))

# Timestamp (freshness)
# ---------------------
# The timestamp role guarantees freshness of the repository metadata. It does
# so by listing the latest snapshot (which in turn lists all the latest
# targets) metadata. A short expiration interval requires the repository to
# regularly issue new timestamp metadata and thus protects the client against
# freeze attacks.
#
# Note that snapshot and timestamp use the same generic wireline metadata
# format. But given that timestamp metadata always has only one entry in its
# 'meta' field, i.e. for the latest snapshot file, the timestamp object
# provides the shortcut 'snapshot_meta'.
roles["timestamp"] = Metadata(Timestamp(expires=_in(1)))

# Root (root of trust)
# --------------------
# The root role serves as root of trust for all top-level roles, including
# itself. It does so by mapping cryptographic keys to roles, i.e. the keys that
# are authorized to sign any top-level role metadata, and signing thresholds,
# i.e. how many authorized keys are required for a given role (see 'roles'
# field). This is called top-level delegation.
#
# In addition, root provides all public keys to verify these signatures (see
# 'keys' field), and a configuration parameter that describes whether a
# repository uses consistent snapshots (see section 'Persist metadata' below
# for more details).

# Create root metadata object
roles["root"] = Metadata(Root(expires=_in(365)))

# For this example, we generate one 'ed25519' key pair for each top-level role
# using python-tuf's in-house crypto library.
# See https://github.com/secure-systems-lab/securesystemslib for more details
# about key handling, and don't forget to password-encrypt your private keys!
for name in ["targets", "snapshot", "timestamp", "root"]:
    signers[name] = CryptoSigner.generate_ecdsa()
    roles["root"].signed.add_key(signers[name].public_key, name)

# NOTE: We only need the public part to populate root, so it is possible to use
# out-of-band mechanisms to generate key pairs and only expose the public part
# to whoever maintains the root role. As a matter of fact, the very purpose of
# signature thresholds is to avoid having private keys all in one place.

# Signature thresholds
# --------------------
# Given the importance of the root role, it is highly recommended to require a
# threshold of multiple keys to sign root metadata. For this example we
# generate another root key (you can pretend it's out-of-band) and increase the
# required signature threshold.
another_root_signer = CryptoSigner.generate_ecdsa()
roles["root"].signed.add_key(another_root_signer.public_key, "root")
roles["root"].signed.roles["root"].threshold = 2


# Sign top-level metadata (in-band)
# =================================
# In this example we have access to all top-level signing keys, so we can use
# them to create and add a signature for each role metadata.
for name in ["targets", "snapshot", "timestamp", "root"]:
    roles[name].sign(signers[name])


# Persist metadata (consistent snapshot)
# ======================================
# It is time to publish the first set of metadata for a client to safely
# download the target file that we have registered for this example repository.
#
# For the purpose of this example we will follow the consistent snapshot naming
# convention for all metadata. This means that each metadata file, must be
# prefixed with its version number, except for timestamp. The naming convention
# also affects the target files, but we don't cover this in the example. See
# the TUF specification for more details:
# https://theupdateframework.github.io/specification/latest/#writing-consistent-snapshots
#
# Also note that the TUF specification does not mandate a wireline format. In
# this demo we use a non-compact JSON format and store all metadata in
# temporary directory at CWD for review.
PRETTY = JSONSerializer(compact=False)
TMP_DIR = tempfile.mkdtemp(dir=os.getcwd())

for name in ["root", "targets", "snapshot"]:
    filename = f"{roles[name].signed.version}.{roles[name].signed.type}.json"
    path = os.path.join(TMP_DIR, filename)
    roles[name].to_file(path, serializer=PRETTY)

roles["timestamp"].to_file(
    os.path.join(TMP_DIR, "timestamp.json"), serializer=PRETTY
)


# Threshold signing (out-of-band)
# ===============================
# As mentioned above, using signature thresholds usually entails that not all
# signing keys for a given role are in the same place. Let's briefly pretend
# this is the case for the second root key we registered above, and we are now
# on that key owner's computer. All the owner has to do is read the metadata
# file, sign it, and write it back to the same file, and this can be repeated
# until the threshold is satisfied.
root_path = os.path.join(TMP_DIR, "1.root.json")
root = Metadata.from_file(root_path)
root.sign(another_root_signer, append=True)
root.to_file(root_path, serializer=PRETTY)


# Targets delegation
# ==================
# Similar to how the root role delegates responsibilities about integrity,
# consistency and freshness to the corresponding top-level roles, a targets
# role may further delegate its responsibility for target files (or a subset
# thereof) to other targets roles. This allows creation of a granular trust
# hierarchy, and further reduces the impact of a single role compromise.
#
# In this example the top-level targets role trusts a new "python-scripts"
# targets role to provide integrity for any target file that ends with ".py".
delegatee_name = "python-scripts"
signers[delegatee_name] = CryptoSigner.generate_ecdsa()

# Delegatee
# ---------
# Create a new targets role, akin to how we created top-level targets above, and
# add target file info from above according to the delegatee's responsibility.
roles[delegatee_name] = Metadata[Targets](
    signed=Targets(
        version=1,
        spec_version=SPEC_VERSION,
        expires=_in(7),
        targets={target_path: target_file_info},
    ),
    signatures={},
)


# Delegator
# ---------
# Akin to top-level delegation, the delegator expresses its trust in the
# delegatee by authorizing a threshold of cryptographic keys to provide
# signatures for the delegatee metadata. It also provides the corresponding
# public key store.
# The delegation info defined by the delegator further requires the provision
# of a unique delegatee name and constraints about the target files the
# delegatee is responsible for, e.g. a list of path patterns. For details about
# all configuration parameters see
# https://theupdateframework.github.io/specification/latest/#delegations
delegatee_key = signers[delegatee_name].public_key
roles["targets"].signed.delegations = Delegations(
    keys={delegatee_key.keyid: delegatee_key},
    roles={
        delegatee_name: DelegatedRole(
            name=delegatee_name,
            keyids=[delegatee_key.keyid],
            threshold=1,
            terminating=True,
            paths=["manual_repo/*.py"],
        ),
    },
)

# Remove target file info from top-level targets (delegatee is now responsible)
del roles["targets"].signed.targets[target_path]

# Increase expiry (delegators should be less volatile)
roles["targets"].signed.expires = _in(365)


# Snapshot + Timestamp + Sign + Persist
# -------------------------------------
# In order to publish a new consistent set of metadata, we need to update
# dependent roles (snapshot, timestamp) accordingly, bumping versions of all
# changed metadata.

# Bump targets version
roles["targets"].signed.version += 1

# Update snapshot to account for changed and new targets metadata
roles["snapshot"].signed.meta["targets.json"].version = roles[
    "targets"
].signed.version
roles["snapshot"].signed.meta[f"{delegatee_name}.json"] = MetaFile(version=1)
roles["snapshot"].signed.version += 1

# Update timestamp to account for changed snapshot metadata
roles["timestamp"].signed.snapshot_meta.version = roles[
    "snapshot"
].signed.version
roles["timestamp"].signed.version += 1

# Sign and write metadata for all changed roles, i.e. all but root
for role_name in ["targets", "python-scripts", "snapshot", "timestamp"]:
    roles[role_name].sign(signers[role_name])

    # Prefix all but timestamp with version number (see consistent snapshot)
    filename = f"{role_name}.json"
    if role_name != "timestamp":
        filename = f"{roles[role_name].signed.version}.{filename}"

    roles[role_name].to_file(os.path.join(TMP_DIR, filename), serializer=PRETTY)


# Root key rotation (recover from a compromise / key loss)
# ========================================================
# TUF makes it easy to recover from a key compromise in-band. Given the trust
# hierarchy through top-level and targets delegation you can easily
# replace compromised or lost keys for any role using the delegating role, even
# for the root role.
# However, since root authorizes its own keys, it always has to be signed with
# both the threshold of keys from the previous version and the threshold of
# keys from the new version. This establishes a trusted line of continuity.
#
# In this example we will replace a root key, and sign a new version of root
# with the threshold of old and new keys. Since one of the previous root keys
# remains in place, it can be used to count towards the old and new threshold.
new_root_signer = CryptoSigner.generate_ecdsa()

roles["root"].signed.revoke_key(signers["root"].public_key.keyid, "root")
roles["root"].signed.add_key(new_root_signer.public_key, "root")
roles["root"].signed.version += 1

roles["root"].signatures.clear()
for signer in [signers["root"], another_root_signer, new_root_signer]:
    roles["root"].sign(signer, append=True)

roles["root"].to_file(
    os.path.join(TMP_DIR, f"{roles['root'].signed.version}.root.json"),
    serializer=PRETTY,
)
