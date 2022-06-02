"""Script for generating new metadata files."""

# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

from securesystemslib.signer import SSlibSigner

from tests import utils
from tuf.api.metadata import Key, Metadata, Root, Snapshot, Targets, Timestamp
from tuf.api.serialization.json import JSONSerializer

# Hardcode keys and expiry time to achieve reproducibility.
public_values: List[str] = [
    "b11d2ff132c033a657318c74c39526476c56de7556c776f11070842dbc4ac14c",
    "250f9ae3d1d3d5c419a73cfb4a470c01de1d5d3d61a3825416b5f5d6b88f4a30",
    "82380623abb9666d4bf274b1a02577469445a972e5650d270101faa5107b19c8",
    "0e6738fc1ac6fb4de680b4be99ecbcd99b030f3963f291277eef67bb9bd123e9",
]
private_values: List[str] = [
    "510e5e04d7a364af850533856eacdf65d30cc0f8803ecd5fdc0acc56ca2aa91c",
    "e6645b00312c8a257782e3e61e85bafda4317ad072c52251ef933d480c387abd",
    "cd13dd2180334b24c19b32aaf27f7e375a614d7ba0777220d5c2290bb2f9b868",
    "7e2e751145d1b22f6e40d4ba2aa47158207acfd3c003f1cbd5a08141dfc22a15",
]
keyids: List[str] = [
    "5822582e7072996c1eef1cec24b61115d364987faa486659fe3d3dce8dae2aba",
    "09d440e3725cec247dcb8703b646a87dd2a4d75343e8095c036c32795eefe3b9",
    "3458204ed467519c19a5316eb278b5608472a1bbf15850ebfb462d5315e4f86d",
    "2be5c21e3614f9f178fb49c4a34d0c18ffac30abd14ced917c60a52c8d8094b7",
]

keys: Dict[str, Key] = {}
for index in range(4):
    keys[f"ed25519_{index}"] = Key.from_securesystemslib_key(
        {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyid": keyids[index],
            "keyval": {
                "public": public_values[index],
                "private": private_values[index],
            },
        }
    )

expires_str = "2050-01-01T00:00:00Z"
EXPIRY = datetime.strptime(expires_str, "%Y-%m-%dT%H:%M:%SZ")
OUT_DIR = "generated_data/ed25519_metadata"
if not os.path.exists(OUT_DIR):
    os.mkdir(OUT_DIR)

SERIALIZER = JSONSerializer()


def verify_generation(md: Metadata, path: str) -> None:
    """Verify that newly generated file equals the locally stored one.

    Args:
        md: Newly generated metadata object.
        path: Path to the locally stored metadata file.
    """
    with open(path, "rb") as f:
        static_md_bytes = f.read()
        md_bytes = md.to_bytes(SERIALIZER)
        if static_md_bytes != md_bytes:
            raise ValueError(
                f"Generated data != local data at {path}. Generate a new "
                + "metadata with 'python generated_data/generate_md.py'"
            )


def generate_all_files(
    dump: Optional[bool] = False, verify: Optional[bool] = False
) -> None:
    """Generate a new repository and optionally verify it.

    Args:
        dump: Wheter to dump the newly generated files.
        verify: Whether to verify the newly generated files with the
            local staored.
    """
    md_root = Metadata(Root(expires=EXPIRY))
    md_timestamp = Metadata(Timestamp(expires=EXPIRY))
    md_snapshot = Metadata(Snapshot(expires=EXPIRY))
    md_targets = Metadata(Targets(expires=EXPIRY))

    md_root.signed.add_key(keys["ed25519_0"], "root")
    md_root.signed.add_key(keys["ed25519_1"], "timestamp")
    md_root.signed.add_key(keys["ed25519_2"], "snapshot")
    md_root.signed.add_key(keys["ed25519_3"], "targets")

    for i, md in enumerate([md_root, md_timestamp, md_snapshot, md_targets]):
        assert isinstance(md, Metadata)
        signer = SSlibSigner(
            {
                "keytype": "ed25519",
                "scheme": "ed25519",
                "keyid": keyids[i],
                "keyval": {
                    "public": public_values[i],
                    "private": private_values[i],
                },
            }
        )
        md.sign(signer)
        path = os.path.join(OUT_DIR, f"{md.signed.type}_with_ed25519.json")
        if verify:
            verify_generation(md, path)

        if dump:
            md.to_file(path, SERIALIZER)


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    # To generate a new set of metadata files this script is supposed to be run
    # from the "tests" folder.
    generate_all_files(dump=True)
