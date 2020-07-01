# 1st-party.
from tuf.api.keys import (
    Keyring,
    Threshold,
    get_private_keys_from_keyring,
    get_public_keys_from_keyring,
    write_and_read_new_keys,
)

# 2nd-party.
from datetime import datetime
from typing import Any, Dict, List, Optional

import json

# 3rd-party.
from dateutil.relativedelta import relativedelta
import iso8601
from securesystemslib.formats import encode_canonical
from securesystemslib.keys import create_signature, verify_signature
from securesystemslib.util import load_json_file
import tuf.formats
from tuf.repository_lib import (
    _get_written_metadata,
    _strip_version_number,
    generate_snapshot_metadata,
    generate_targets_metadata,
    generate_timestamp_metadata,
)

# Types.
JsonDict = Dict[str, Any]

# Classes.

class Metadata:
    # By default, a Metadata would be a rather empty one.
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(), keyring: Optional[Keyring] = None, version: int = 1) -> None:
        self.consistent_snapshot = consistent_snapshot

        self.keyring = keyring
        self.expiration = expiration

        assert version >= 1, f'{version} < 1'
        self.version = version

    # And you would use this method to populate it from a file.
    def read_from_json(self, filename: str) -> None:
        signable = load_json_file(filename)

        # TODO: use some basic schema checks
        self.signatures = signable['signatures']
        self.signed = signable['signed']

        # TODO: replace with dateutil.parser.parse?
        self.expiration = iso8601.parse_date(self.signed['expires'])
        self.version = self.signed['version']

        fn, fn_ver = _strip_version_number(filename, True)
        if fn_ver:
            assert fn_ver == self.version, f'{fn_ver} != {self.version}'
            self.consistent_snapshot = True
        else:
            self.consistent_snapshot = False

    @property
    def signable(self) -> JsonDict:
        """
        To be overridden by the inheriting class.
        The idea is to serialize this object into the signable we expect.
        """
        raise NotImplementedError()

    def bump_version(self) -> None:
        self.version = self.version + 1

    def bump_expiration(self, delta: relativedelta = relativedelta(days=1)) -> None:
        self.expiration = self.expiration + delta

    def signed(self) -> str:
        return encode_canonical(self.signable['signed']).encode('utf-8')

    def signatures(self) -> List:
        return self.signable['signatures']

    def sign(self) -> JsonDict:
        def update_signature(signatures, keyid, signature):
            updated = False
            keyid_signature = {'keyid':keyid, 'sig':signature}
            for idx, keyid_sig in enumerate(signatures):
                if keyid_sig['keyid'] == keyid:
                    signatures[idx] = keyid_signature
                    updated = True
            if not updated:
                signatures.append({'keyid':keyid, 'sig':signature})

        signed = self.signed
        signatures = self.signatures

        for keypair in self.keyring.keypairs:        
            signature = create_signature(keypair.private.obj, signed)
            keyid  = keypair.private.obj['keyid']    
            update_signature(signatures, keyid, signature)

        self.signatures = signatures
        return {'signed': signed, 'signatures': signatures}

    def verify(self) -> bool:
        signed = self.signed
        signatures = self.signatures
        good_signatures = 0

        for keypair in self.keyring.keypairs:
            try:
                keyid = keypair.public.obj['keyid']
                for signature in signatures:
                    if signature['keyid'] == keyid:
                        if verify_signature(keypair.public.obj, signature, signed):
                            good_signatures += 1
                        break
            except:
                logging.warning(f'Could not verify signature for key {keyid}')
                continue

        return good_signatures >= self.keyring.threshold.m

    def write_to_json(self, filename: str) -> None:
        with open(filename, 'r+b') as f:
            f.write(_get_written_metadata(self.sign()))

class Timestamp(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: Keyring = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, keyring, version)

    def signable(self):
        expires = self.expiration.replace(tzinfo=None).isoformat()+'Z'
        filedict = self.signed['meta']
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.TIMESTAMP_SCHEMA, version=self.version,
            expires=expires, meta=filedict)

    # Update metadata about the snapshot metadata.
    def update(self, rolename: str, version: int, length: int, hashes: JsonDict):
        fileinfo = self.signed['meta'][f'{rolename}.json']
        fileinfo['version'] = version
        fileinfo['length'] = length
        fileinfo['hashes'] = hashes

class Snapshot(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: Keyring = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, keyring, version)
        self.targets_fileinfo = {}

    def read_from_json(self, filename: str) -> None:
        super().read_from_json(filename)
        meta = self.signed['meta']
        for target_role in meta:
            version = meta[target_role]['version']
            length = meta[target_role].get('length')
            hashes = meta[target_role].get('hashes')
            self.targets_fileinfo[target_role] = tuf.formats.make_metadata_fileinfo(version, length, hashes)

    def signable(self):
        # TODO: probably want to generalise this, a @property.getter in Metadata?
        expires = self.expiration.replace(tzinfo=None).isoformat()+'Z'
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.SNAPSHOT_SCHEMA, version=self.version,
            expires=expires, meta=self.targets_fileinfo)

    # Add or update metadata about the targets metadata.
    def update(self, rolename: str, version: int, length: Optional[int] = None, hashes: Optional[JsonDict] = None):
        self.targets_fileinfo[f'{rolename}.json'] = tuf.formats.make_metadata_fileinfo(version, length, hashes)

class Targets(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: Keyring = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, relativedelta, keyring, version)

    # FIXME
    def signable(self):
        return generate_targets_metadata()

    # Add or update metadata about the target.
    # TODO: how to handle writing consistent targets?
    def update(self, filename: str, fileinfo: JsonDict):
        raise NotImplementedError()
