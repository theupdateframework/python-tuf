# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
A TUF succinct hash bin delegation example using the low-level TUF Metadata API.

The example code in this file demonstrates how to perform succinct hash bin
delegation using the low-level Metadata API.
Succinct hash bin delegation achieves a similar result as using a standard hash
bin delegation, but the delegating metadata is smaller resulting in fewer bytes
to transfer and parse.

See 'basic_repo.py' for a more comprehensive TUF metadata API example.

For a comprehensive explanation of succinct hash bin delegation and the
difference between succinct and standard hash bin delegation read:
https://github.com/theupdateframework/taps/blob/master/tap15.md

NOTE: Metadata files will be written to a 'tmp*'-directory in CWD.
"""
import math
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner

from tuf.api.metadata import (
    Delegations,
    Key,
    Metadata,
    SuccinctRoles,
    TargetFile,
    Targets,
)
from tuf.api.serialization.json import JSONSerializer

# Succinct hash bin delegation
# ============================
# Succinct hash bin delegation aims to distribute a large number of target files
# over multiple delegated targets metadata roles (bins). The consequence is a
# smaller metadata files and thus a lower network overhead for repository-client
# communication.
#
# The assignment of target files to a target's metadata is done automatically,
# based on the byte digest of the target file name.
#
# The number of the bins, name prefix for all bins and key threshold are all
# attributes that need to be configured.

# Number of bins, bit length and bin number computation
# -----------------------------------------------------
# The right number of bins depends on the expected number of target files in a
# repository. For the purpose of this example we choose:
NUMBER_OF_BINS = 32
#
# The bit length is the number of bins that will be used to calculate the bin
# for each target path. It can be calculated directly from NUMBER_OF_BINS:
BIT_LENGTH = int(math.log2(NUMBER_OF_BINS))

# Delegated role (bin) name format
# --------------------------------
# Each bin has a name in the format of f"{NAME_PREFIX}-{bin_number}".
#
# Name prefix is the common prefix of all delegated target roles (bins).
# For our example it will be:
NAME_PREFIX = "delegated_bin"
#
# The suffix "bin_number" is a zero-padded hexadecimal number of that
# particular bin.

# Keys and threshold
# ------------------
# Given that the primary concern of succinct hash bin delegation is to reduce
# network overhead it was decided that all bins will be signed by the same
# set of one or more signing keys.
#
# Before generating the keys a decision has to be made about the number of keys
# required for signing the bins or in other words the value of the threshold.
# For the purpose of this example we choose the threshold to be:
THRESHOLD = 1
# Note: If THRESHOLD is changed to more than 1 the example should be modified.


def create_key() -> Tuple[Key, SSlibSigner]:
    """Generates a new Key and Signer."""
    sslib_key = generate_ed25519_key()
    return Key.from_securesystemslib_key(sslib_key), SSlibSigner(sslib_key)


key, signer = create_key()

# Top level targets instance with succinct hash bin delegation
# ------------------------------------------------------------
# NOTE: See "Targets" and "Targets delegation" paragraphs in 'basic_repo.py'
# example for more details about the Targets object.
#
# Now we have all the ingredients needed to create a Targets instance using
# succinct hash bin delegation.
#
# First, we create a Targets metadata instance without any delegations.

# We define expire as 7 days from today.
expiration_date = datetime.utcnow().replace(microsecond=0) + timedelta(days=7)
targets = Metadata(Targets(expires=expiration_date))

# Then, we want to add delegations and with it information about the succinct
# hash bin delegations which are represented by SuccinctRoles instance.
#
# Using succinct hash bin delegations has two restrictions:
# 1) no other delegated roles have to be used
# 2) only one succinct hash bin delegation can exist for one targets role

# We have all information needed to create a SuccinctRoles instance:
succinct_roles = SuccinctRoles(
    keyids=[],
    threshold=THRESHOLD,
    bit_length=BIT_LENGTH,
    name_prefix=NAME_PREFIX,
)

# Now we will populate the keyids by using the succinct_roles_keys list.
delegations_keys_info: Dict[str, Key] = {}
succinct_roles.keyids.append(key.keyid)
delegations_keys_info[key.keyid] = key

# We are ready to define the Delegations instance which we will add to targets.
# As mentioned, standard roles are not allowed together with succinct_roles.
delegations = Delegations(
    delegations_keys_info, roles=None, succinct_roles=succinct_roles
)

targets.signed.delegations = delegations

# Delegated targets (bins) roles
# ------------------------------
# We have defined the top-level targets metadata instance which utilizes
# succinct_roles. With succinct_roles we have defined the bins number, common
# bin properties and keys information, but we haven't actually created the
# bins targets metadata instances.

# mypy linter requires that we verify that succinct_roles is not None
assert targets.signed.delegations.succinct_roles is not None

# We can get all bin names for a SuccinctRoles instance with get_roles()
delegated_bins: Dict[str, Metadata[Targets]] = {}
for delegated_bin_name in targets.signed.delegations.succinct_roles.get_roles():
    delegated_bins[delegated_bin_name] = Metadata(
        Targets(expires=expiration_date)
    )

# Add target file inside a delegated role (bin)
# ---------------------------------------------
# For the purpose of this example we will protect the integrity of this very
# example script by adding its file info to the corresponding bin metadata.

# NOTE: See "Targets" paragraph in 'basic_repo.py' example for more details
# about adding target file infos to targets metadata.
local_path = Path(__file__).resolve()
target_path = f"{local_path.parts[-2]}/{local_path.parts[-1]}"
target_file_info = TargetFile.from_file(target_path, str(local_path))

# We don't know yet in which delegated role (bin) our target belongs.
# With SuccinctRoles.get_role_for_target() we can get the name of the delegated
# role (bin) responsible for that target_path.
target_bin = targets.signed.delegations.succinct_roles.get_role_for_target(
    target_path
)

# In our example with NUMBER_OF_BINS = 32 and the current file as target_path
# the target_bin is "delegated_bin-0d"

# Now we can add the current target to the bin responsible for it.
delegated_bins[target_bin].signed.targets[target_path] = target_file_info

# Sign and persist
# ----------------
# Sign all metadata and persist to a temporary directory at CWD for review using
# versioned file names. Most notably see 'targets.json' and
# 'delegated_bin-0d.json'. For more information on versioned file names see:
# https://theupdateframework.github.io/specification/latest/#writing-consistent-snapshots

# NOTE: See "Persist metadata" paragraph in 'basic_repo.py' example for more
# details about serialization formats and metadata file name convention.
PRETTY = JSONSerializer(compact=False)
TMP_DIR = tempfile.mkdtemp(dir=os.getcwd())

# Generate a key for targets we haven't added one up to this point.
_, targets_signer = create_key()
targets.sign(targets_signer)
targets.to_file(os.path.join(TMP_DIR, "1.targets.json"), serializer=PRETTY)

for bin_name, bin_target_role in delegated_bins.items():
    file_name = f"1.{bin_name}.json"
    file_path = os.path.join(TMP_DIR, file_name)

    bin_target_role.sign(signer, append=True)

    bin_target_role.to_file(file_path, serializer=PRETTY)
