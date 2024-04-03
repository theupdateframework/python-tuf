# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""A Repository implementation for maintainer and developer tools"""

import contextlib
import copy
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Dict

import requests
from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import Metadata, MetaFile, TargetFile, Targets
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater
from tuf.repository import Repository

logger = logging.getLogger(__name__)


class LocalRepository(Repository):
    """A repository implementation that fetches data from a remote repository

    This implementation fetches metadata from a remote repository, potentially
    creates new versions of metadata, and submits to the remote repository.

    ngclient Updater is used to fetch metadata from remote server: this is good
    because we want to make sure the metadata we modify is verified, but also
    bad because we need some hacks to access the Updaters metadata.
    """

    expiry_period = timedelta(days=1)

    def __init__(self, metadata_dir: str, key_dir: str, base_url: str):
        self.key_dir = key_dir
        if not os.path.isdir(self.key_dir):
            os.makedirs(self.key_dir)

        self.base_url = base_url

        self.updater = Updater(
            metadata_dir=metadata_dir,
            metadata_base_url=f"{base_url}/metadata/",
        )
        self.updater.refresh()

    @property
    def targets_infos(self) -> Dict[str, MetaFile]:
        raise NotImplementedError  # we never call snapshot

    @property
    def snapshot_info(self) -> MetaFile:
        raise NotImplementedError  # we never call timestamp

    def open(self, role: str) -> Metadata:
        """Return cached (or fetched) metadata"""

        # if there is a metadata version fetched from remote, use that
        # HACK: access Updater internals
        trusted_set = self.updater._trusted_set  # noqa: SLF001
        if role in trusted_set:
            # NOTE: The original signature wrapper (Metadata) was verified and
            # discarded upon inclusion in the trusted set. It is safe to use
            # a fresh wrapper. `close` will override existing signatures anyway.
            return Metadata(copy.deepcopy(trusted_set[role]))

        # otherwise we're creating metadata from scratch
        md = Metadata(Targets())
        # this makes version bumping in close() simpler
        md.signed.version = 0
        return md

    def close(self, role_name: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        targets = self.targets()
        role = targets.get_delegated_role(role_name)
        public_key = targets.get_key(role.keyids[0])
        uri = f"file2:{self.key_dir}/{role_name}"

        signer = Signer.from_priv_key_uri(uri, public_key)

        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.sign(signer, append=False)

        # Upload using "api/role"
        uri = f"{self.base_url}/api/role/{role_name}"
        r = requests.post(uri, data=md.to_bytes(JSONSerializer()), timeout=5)
        r.raise_for_status()

    def add_target(self, role: str, targetpath: str) -> bool:
        """Add target to roles metadata and submit new metadata version"""

        # HACK: make sure we have the roles metadata in updater._trusted_set
        # (or that we're publishing the first version)
        # HACK: Assume RepositoryError is because we're just publishing version
        # 1 (so the roles metadata does not exist on server yet)
        with contextlib.suppress(RepositoryError):
            self.updater.get_targetinfo(targetpath)

        data = bytes(targetpath, "utf-8")
        targetfile = TargetFile.from_data(targetpath, data)
        try:
            with self.edit_targets(role) as delegated:
                delegated.targets[targetpath] = targetfile

        except Exception as e:  # noqa: BLE001
            print(f"Failed to submit new {role} with added target: {e}")
            return False

        print(f"Uploaded role {role} v{delegated.version}")
        return True

    def add_delegation(self, role: str) -> bool:
        """Use the (unauthenticated) delegation adding API endpoint"""
        signer = CryptoSigner.generate_ecdsa()

        data = {signer.public_key.keyid: signer.public_key.to_dict()}
        url = f"{self.base_url}/api/delegation/{role}"
        r = requests.post(url, data=json.dumps(data), timeout=5)
        if r.status_code != 200:
            print(f"delegation failed with {r}")
            return False

        # Store the private key using rolename as filename
        with open(f"{self.key_dir}/{role}", "wb") as f:
            f.write(signer.private_bytes)

        print(f"Uploaded new delegation, stored key in {self.key_dir}/{role}")
        return True
