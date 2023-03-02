# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""A Repository implementation for maintainer and developer tools"""

import copy
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict

import requests
from securesystemslib import keys
from securesystemslib.signer import SSlibKey, SSlibSigner

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
        # pylint: disable=protected-access
        if role in self.updater._trusted_set:
            return copy.deepcopy(self.updater._trusted_set[role])

        # otherwise we're creating metadata from scratch
        md = Metadata(Targets())
        # this makes version bumping in close() simpler
        md.signed.version = 0
        return md

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.utcnow() + self.expiry_period

        with open(f"{self.key_dir}/{role}", "rt", encoding="utf-8") as f:
            signer = SSlibSigner(json.loads(f.read()))

        md.sign(signer, append=False)

        # Upload using "api/role"
        uri = f"{self.base_url}/api/role/{role}"
        r = requests.post(uri, data=md.to_bytes(JSONSerializer()), timeout=5)
        r.raise_for_status()

    def add_target(self, role: str, targetpath: str) -> bool:
        """Add target to roles metadata and submit new metadata version"""

        # HACK: make sure we have the roles metadata in updater._trusted_set
        # (or that we're publishing the first version)
        try:
            self.updater.get_targetinfo(targetpath)
        except RepositoryError:
            # HACK Assume this is because we're just publishing version 1
            # (so the roles metadata does not exist on server yet)
            pass

        data = bytes(targetpath, "utf-8")
        targetfile = TargetFile.from_data(targetpath, data)
        try:
            with self.edit_targets(role) as delegated:
                delegated.targets[targetpath] = targetfile

        except Exception as e:  # pylint: disable=broad-except
            print(f"Failed to submit new {role} with added target: {e}")
            return False

        print(f"Uploaded role {role} v{delegated.version}")
        return True

    def add_delegation(self, role: str) -> bool:
        """Use the (unauthenticated) delegation adding API endpoint"""
        keydict = keys.generate_ed25519_key()
        pubkey = SSlibKey.from_securesystemslib_key(keydict)

        data = {pubkey.keyid: pubkey.to_dict()}
        url = f"{self.base_url}/api/delegation/{role}"
        r = requests.post(url, data=json.dumps(data), timeout=5)
        if r.status_code != 200:
            print(f"delegation failed with {r}")
            return False

        # Store the private key using rolename as filename
        with open(f"{self.key_dir}/{role}", "wt", encoding="utf-8") as f:
            f.write(json.dumps(keydict))

        print(f"Uploaded new delegation, stored key in {self.key_dir}/{role}")
        return True
