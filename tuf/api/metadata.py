# Imports.

# 1st-party.
from tuf.api.keys import KeyRing

# 2nd-party.
from datetime import datetime
from typing import Any, Dict, List, Optional

import json
import tempfile

# 3rd-party.
from dateutil.relativedelta import relativedelta
from securesystemslib.formats import encode_canonical
from securesystemslib.util import load_json_file, persist_temp_file
from securesystemslib.storage import StorageBackendInterface
import tuf.formats
from tuf.repository_lib import (
    _get_written_metadata,
    _strip_version_number,
    generate_snapshot_metadata,
    generate_targets_metadata,
    generate_timestamp_metadata,
)

import iso8601

# Types.

JsonDict = Dict[str, Any]

# Classes.

class Metadata:
    # By default, a Metadata would be a rather empty one.
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(), keyring: Optional[KeyRing] = None, version: int = 1) -> None:
        self.consistent_snapshot = consistent_snapshot

        self.keyring = keyring
        self._expiration = expiration

        assert version >= 1, f'{version} < 1'
        self.version = version

        self._signed = {}
        self._signatures = []

    # And you would use this method to populate it from a file.
    @classmethod
    def read_from_json(cls, filename: str, storage_backend: StorageBackendInterface = None) -> None:
        signable = load_json_file(filename, storage_backend)
        tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

        signatures = signable['signatures']
        signed = signable['signed']

        # We always intend times to be UTC
        expiration = iso8601.parse_date(signed['expires']).replace(tzinfo=None)
        version = signed['version']

        fn, fn_ver = _strip_version_number(filename, True)
        if fn_ver:
            assert fn_ver == self.version, f'{fn_ver} != {self.version}'
            consistent_snapshot = True
        else:
            consistent_snapshot = False

        metadata = cls(consistent_snapshot=consistent_snapshot,
                       expiration=expiration,
                       version=version)

        metadata._signatures = signatures
        metadata._signed = signed

        return metadata

    @property
    def signable(self) -> JsonDict:
        return {"signatures": self.signatures,
                "signed": self.signed}

    @property
    def signed_bytes(self) -> bytes:
        return encode_canonical(self.signed).encode('UTF-8')

    @property
    def signed(self) -> str:
        raise NotImplementedError

    @property
    def signatures(self) -> List[JsonDict]:
        return self._signatures

    @property
    def expires(self) -> str:
        """The expiration property as a string"""
        return self._expiration.isoformat()+'Z'

    @property
    def expiration(self) -> datetime:
        return self._expiration

    @expiration.setter
    def expiration(self, datetime) -> None:
        # We always treat dates as UTC
        self._expiration = datetime.replace(tzinfo=None)

    def bump_version(self) -> None:
        self.version = self.version + 1

    def bump_expiration(self, delta: relativedelta = relativedelta(days=1)) -> None:
        self._expiration = self._expiration + delta

    def sign(self) -> JsonDict:
        def update_signature(signatures, keyid, signature):
            updated = False
            keyid_signature = {'keyid':keyid, 'sig':signature}
            for idx, keyid_sig in enumerate(signatures):
                if keyid_sig['keyid'] == keyid:
                    signatures[idx] = keyid_signature
                    updated = True
            if not updated:
                signatures.append(keyid_signature)

        signed_bytes = self.signed_bytes
        signatures = self._signatures

        for key in self.keyring.keys:
            signature = key.sign(signed_bytes)
            update_signature(signatures, key.keyid, signature)

        self._signatures = signatures
        return self.signable

    def verify(self) -> bool:
        signed_bytes = self.signed_bytes
        signatures = self.signatures
        verified_keyids = {}

        for signature in signatures:
            # TODO: handle an empty keyring
            for key in self.keyring.keys:
                keyid = key.keyid
                if keyid == signature['keyid']:
                    try:
                        verified = key.verify(signed_bytes, signature)
                    except:
                        logging.exception(f'Could not verify signature for key {keyid}')
                        continue
                    else:
                        # Avoid https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6174
                        verified_keyids |= keyid
                        break

        return len(verified_keyids) >= self.keyring.threshold.min

    def write_to_json(self, filename: str, storage_backend: StorageBackendInterface = None) -> None:
         with tempfile.TemporaryFile() as f:
            f.write(_get_written_metadata(self.sign()).encode_canonical())
            persist_temp_file(f, filename, storage_backend)

class Timestamp(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: KeyRing = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, keyring, version)
        self.snapshot_fileinfo = {}

    @classmethod
    def read_from_json(cls, filename: str) -> None:
        md = Metadata.read_from_json(filename)
        timestamp = cls(md.consistent_snapshot, md.expiration, md.keyring, md.version)
        timestamp.snapshot_fileinfo = md._signed['meta']
        tuf.formats.TIMESTAMP_SCHEMA.check_match(timestamp.signed)
        timestamp._signatures = md._signatures
        return timestamp

    @property
    def signed(self) -> JsonDict:
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.TIMESTAMP_SCHEMA, version=self.version,
            expires=self.expires, meta=self.snapshot_fileinfo)

    # Update metadata about the snapshot metadata.
    def update(self, version: int, length: int, hashes: JsonDict):
        fileinfo = self.snapshot_fileinfo.get('snapshot.json', {})
        fileinfo['version'] = version
        fileinfo['length'] = length
        fileinfo['hashes'] = hashes
        self.snapshot_fileinfo['snapshot.json'] = fileinfo

class Snapshot(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: KeyRing = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, keyring, version)
        self.targets_fileinfo = {}

    @classmethod
    def read_from_json(cls, filename: str) -> None:
        md = Metadata.read_from_json(filename)
        snapshot = cls(md.consistent_snapshot, md.expiration, md.keyring, md.version)
        meta = md._signed['meta']
        for target_role in meta:
            version = meta[target_role]['version']
            length = meta[target_role].get('length')
            hashes = meta[target_role].get('hashes')
            snapshot.targets_fileinfo[target_role] = tuf.formats.make_metadata_fileinfo(version, length, hashes)
        tuf.formats.SNAPSHOT_SCHEMA.check_match(snapshot.signed)
        snapshot._signatures = md._signatures
        return snapshot

    @property
    def signed(self):
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.SNAPSHOT_SCHEMA, version=self.version,
            expires=self.expires, meta=self.targets_fileinfo)

    # Add or update metadata about the targets metadata.
    def update(self, rolename: str, version: int, length: Optional[int] = None, hashes: Optional[JsonDict] = None):
        self.targets_fileinfo[f'{rolename}.json'] = tuf.formats.make_metadata_fileinfo(version, length, hashes)

class Targets(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: KeyRing = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, keyring, version)
        self.targets = {}
        self.delegations = {}

    @classmethod
    def read_from_json(cls, filename: str) -> None:
        targets = Metadata.read_from_json(filename)
        targets.targets = self._signed['targets']
        targets.delegations = self._signed.get('delegations', {})
        tuf.formats.TARGETS_SCHEMA.check_match(targets.signed)
        targets._signatures = md._signatures
        return targets

    @property
    def signed(self):
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.TARGETS_SCHEMA,
            version=self.version,
            expires=self.expires,
            targets=self.targets,
            delegations=self.delegations)

    # Add or update metadata about the target.
    def update(self, filename: str, fileinfo: JsonDict):
        self.targets[filename] = fileinfo
