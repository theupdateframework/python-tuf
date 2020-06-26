# 1st-party.
from keys import (
    Keyring,
    Threshold,
    get_private_keys_from_keyring,
    get_public_keys_from_keyring,
    sorted_list_of_keyids,
    write_and_read_new_keys,
)

# 2nd-party.
from datetime import datetime
from typing import Any, Dict, List, Optional

import json

# 3rd-party.
from dateutil.relativedelta import relativedelta
from securesystemslib.formats import encode_canonical
from securesystemslib.keys import create_signature, verify_signature
from securesystemslib.util import load_json_file
from tuf.repository_lib import (
    _get_written_metadata,
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

        assert version > 1, f'{version} < 1'
        self.version = version

    # And you would use this method to populate it from a file.
    def read_from_json(self, filename: str) -> None:
        signable = load_json_file(filename)

        # TODO: use some basic schema checks
        signatures = signable['signatures']
        signed = signable['signed']

        self.expiration = datetime.strptime(signed['expiration'], '%b %d %Y %I:%M%p')
        self.version = signed['version']

    @property
    def signable(self) -> JsonDict:
        """
        To be overridden by the inheriting class.
        The idea is to serialize this object into the signable we expect.
        """
        raise NotImplementedError()

    def signed(self) -> str:
        return encode_canonical(self.signable['signed']).encode('utf-8')

    def signatures(self) -> List:
        return self.signable['signatures']

    # TODO: We need to update the expiration timestamp using self.expiration.
    # Oh, and bump the version number.
    # And, oh, take care of consistent snapshot of metadata.
    def sign(self) -> JsonDict:
        # TODO: not so simple. IDK why we don't index signatures by
        # keyids,but we need to walk through the list to find any previous
        # signature by the same keyid.
        def update_signature(signatures, keyid, signature):
            raise NotImplementedError()

        signed = self.signed
        signatures = self.signatures

        for keypair in self.keyring.keypairs:        
            signature = create_signature(keypair.private.obj, signed)
            keyid  = keypair.private.obj['keyid']    
            update_signature(signatures, keyid, signature)
    
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
        super().__init__(consistent_snapshot, expiration, relativedelta, keyring, version)

    # FIXME
    def signable(self):
        return generate_timestamp_metadata()

    # Update metadata about the snapshot metadata.
    def update(self, rolename: str, version: int, length: int, hashes: JsonDict):
        raise NotImplementedError()

class Snapshot(Metadata):
    def __init__(self, consistent_snapshot: bool = True, expiration: relativedelta = relativedelta(days=1), keyring: Keyring = None, version: int = 1):
        super().__init__(consistent_snapshot, expiration, relativedelta, keyring, version)

    # FIXME
    def signable(self):
        return generate_snapshot_metadata()

    # Add or update metadata about the targets metadata.
    def update(self, rolename: str, version: int, length: Optional[int] = None, hashes: Optional[JsonDict] = None):
        raise NotImplementedError()

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
