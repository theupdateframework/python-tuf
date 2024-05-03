# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
A TUF succinct hash bin delegation example using the low-level TUF Metadata API.

The example code in this file demonstrates how to perform succinct hash bin
delegation using the low-level Metadata API.
Succinct hash bin delegation achieves a similar result as using a standard hash
bin delegation, but the delegating metadata is smaller, resulting in fewer bytes
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict

from securesystemslib.signer import CryptoSigner

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
# over multiple delegated targets metadata roles (bins). The consequence is
# smaller metadata files and thus a lower network overhead for repository-client
# communication.
#
# The assignment of target files to a target's metadata is done automatically,
# based on the byte digest of the target file name.
#
# The number of bins, name prefix for all bins and key threshold are all
# attributes that need to be configured.

# Number of bins, bit length and bin number computation
# -----------------------------------------------------
# Determining the correct number of bins is dependent on the expected number of
# target files in a repository. For the purpose of this example we choose:
NUMBER_OF_BINS = 32
#
# The number of bins will determine the number of bits in a target path
# considered in assigning the target to a bin.
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
# Succinct hash bin delegation uses the same key(s) to sign all bins. This is
# acceptable because the primary concern of this type of delegation is to reduce
# network overhead. For the purpose of this example only one key is required.
THRESHOLD = 1


# Create one signing key for all bins, and one for the delegating targets role.
bins_signer = CryptoSigner.generate_ecdsa()
bins_key = bins_signer.public_key
targets_signer = CryptoSigner.generate_ecdsa()

# Delegating targets role
# -----------------------
# Akin to regular targets delegation, the delegating role ships the public keys
# of the delegated roles. However, instead of providing individual delegation
# information about each role, one single `SuccinctRoles` object is used to
# provide the information for all delegated roles (bins).

# NOTE: See "Targets" and "Targets delegation" paragraphs in 'basic_repo.py'
# example for more details about the Targets object.

expiration_date = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
    days=7
)
targets = Metadata(Targets(expires=expiration_date))

succinct_roles = SuccinctRoles(
    keyids=[bins_key.keyid],
    threshold=THRESHOLD,
    bit_length=BIT_LENGTH,
    name_prefix=NAME_PREFIX,
)
delegations_keys_info: Dict[str, Key] = {}
delegations_keys_info[bins_key.keyid] = bins_key

targets.signed.delegations = Delegations(
    delegations_keys_info, roles=None, succinct_roles=succinct_roles
)

# Delegated targets roles (bins)
# ------------------------------
# We can use the SuccinctRoles object from the delegating role above to iterate
# over all bin names in the delegation and create the corresponding metadata.

assert targets.signed.delegations.succinct_roles is not None  # make mypy happy

delegated_bins: Dict[str, Metadata[Targets]] = {}
for delegated_bin_name in targets.signed.delegations.succinct_roles.get_roles():
    delegated_bins[delegated_bin_name] = Metadata(
        Targets(expires=expiration_date)
    )

# Add target file inside a delegated role (bin)
# ---------------------------------------------
# For the purpose of this example we will protect the integrity of this
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
# Sign all metadata and write to a temporary directory at CWD for review using
# versioned file names. Most notably see '1.targets.json' and
# '1.delegated_bin-0d.json'.

# NOTE: See "Persist metadata" paragraph in 'basic_repo.py' example for more
# details about serialization formats and metadata file name convention.
PRETTY = JSONSerializer(compact=False)
TMP_DIR = tempfile.mkdtemp(dir=os.getcwd())


targets.sign(targets_signer)
targets.to_file(os.path.join(TMP_DIR, "1.targets.json"), serializer=PRETTY)

for bin_name, bin_target_role in delegated_bins.items():
    file_name = f"1.{bin_name}.json"
    file_path = os.path.join(TMP_DIR, file_name)

    bin_target_role.sign(bins_signer, append=True)

    bin_target_role.to_file(file_path, serializer=PRETTY)
