"""TUF role metadata model.

This module provides container classes for TUF role metadata, including methods
to read/serialize/write from and to JSON, perform TUF-compliant metadata
updates, and create and verify signatures.

TODO:

 * Add docstrings

 * Finalize/Document Verify/Sign functions (I am not fully sure about expected
   behavior). See
   https://github.com/theupdateframework/tuf/pull/1060#issuecomment-660056376

 * Validation (some thoughts ...)
   - Avoid schema, see secure-systems-lab/securesystemslib#183
   - Provide methods to validate JSON representation (at user boundary)
   - Fail on bad json metadata in read_from_json method
   - Be lenient on bad/invalid metadata objects in memory, they might be
     work in progress. E.g. it might be convenient to create empty metadata
     and assign attributes later on.
   - Fail on bad json metadata in write_to_json method, but with option to
     disable check as there might be a justified reason to write WIP
     metadata to json.

 * Add Root metadata class

"""
# Imports

from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import json
import logging
import tempfile

from securesystemslib.formats import encode_canonical
from securesystemslib.util import load_json_file, persist_temp_file
from securesystemslib.storage import StorageBackendInterface
from tuf.repository_lib import (
    _strip_version_number
)

import iso8601
import tuf.formats


# Types

JsonDict = Dict[str, Any]


# Classes.

class Metadata():
    def __init__(
            self, signed: 'Signed' = None, signatures: list = None) -> None:
        # TODO: How much init magic do we want?
        self.signed = signed
        self.signatures = signatures

    def as_dict(self) -> JsonDict:
        return {
            'signatures': self.signatures,
            'signed': self.signed.as_dict()
        }

    def as_json(self, compact: bool = False) -> None:
        """Returns the optionally compacted JSON representation. """
        return json.dumps(
                self.as_dict(),
                indent=(None if compact else 1),
                separators=((',', ':') if compact else (',', ': ')),
                sort_keys=True)

    # def __update_signature(self, signatures, keyid, signature):
    #     updated = False
    #     keyid_signature = {'keyid':keyid, 'sig':signature}
    #     for idx, keyid_sig in enumerate(signatures):
    #         if keyid_sig['keyid'] == keyid:
    #             signatures[idx] = keyid_signature
    #             updated = True
    #     if not updated:
    #         signatures.append(keyid_signature)

    # def sign(self, key_ring: ???) -> JsonDict:
    #     # FIXME: Needs documentation of expected behavior
    #     signed_bytes = self.signed_bytes
    #     signatures = self.__signatures

    #     for key in key_ring.keys:
    #         signature = key.sign(self.signed_bytes)
    #         self.__update_signature(signatures, key.keyid, signature)

    #     self.__signatures = signatures
    #     return self.signable

    # def verify(self, key_ring: ???) -> bool:
    #     # FIXME: Needs documentation of expected behavior
    #     signed_bytes = self.signed.signed_bytes
    #     signatures = self.signatures
    #     verified_keyids = set()

    #     for signature in signatures:
    #         # TODO: handle an empty keyring
    #         for key in key_ring.keys:
    #             keyid = key.keyid
    #             if keyid == signature['keyid']:
    #                 try:
    #                     verified = key.verify(signed_bytes, signature)
    #                 except:
    #                     logging.exception(f'Could not verify signature for key {keyid}')
    #                     continue
    #                 else:
    #                     # Avoid https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6174
    #                     verified_keyids.add(keyid)

    #                     break

    #     return len(verified_keyids) >= key_ring.threshold.least
    @classmethod
    def read_from_json(
            cls, filename: str,
            storage_backend: Optional[StorageBackendInterface] = None
            ) -> 'Metadata':
        """Loads JSON-formatted TUF metadata from a file storage.

        Arguments:
            filename: The path to read the file from.
            storage_backend: An object that implements
                securesystemslib.storage.StorageBackendInterface. Per default
                a (local) FilesystemBackend is used.

        Raises:
            securesystemslib.exceptions.StorageError: The file cannot be read.
            securesystemslib.exceptions.Error, ValueError: The metadata cannot
                be parsed.

        Returns:
            A TUF Metadata object.

        """
        signable = load_json_file(filename, storage_backend)

        # TODO: Should we use constants?
        # And/or maybe a dispatch table? (<-- maybe too much magic)
        _type = signable['signed']['_type']

        if _type == 'targets':
            inner_cls = Targets
        elif _type == 'snapshot':
            inner_cls = Snapshot
        elif _type == 'timestamp':
            inner_cls = Timestamp
        elif _type == 'root':
            # TODO: implement Root class
            raise NotImplementedError('Root not yet implemented')
        else:
            raise ValueError(f'unrecognized metadata type "{_type}"')

        return Metadata(
                signed=inner_cls(**signable['signed']),
                signatures=signable['signatures'])

    def write_to_json(
            self, filename: str, compact: bool = False,
            storage_backend: StorageBackendInterface = None) -> None:
        """Writes the JSON representation of the instance to file storage.

        Arguments:
            filename: The path to write the file to.
            compact: A boolean indicating if the JSON string should be compact
                    by excluding whitespace.
            storage_backend: An object that implements
                securesystemslib.storage.StorageBackendInterface. Per default
                a (local) FilesystemBackend is used.
        Raises:
            securesystemslib.exceptions.StorageError:
                The file cannot be written.

        """
        with tempfile.TemporaryFile() as f:
            f.write(self.as_json(compact).encode('utf-8'))
            persist_temp_file(f, filename, storage_backend)


class Signed:
    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")

    # TODO: Re-think default values. It might be better to pass some things
    # as args and not es kwargs. Then we'd need to pop those from
    # signable["signed"] in read_from_json and pass them explicitly, which
    # some say is better than implicit. :)
    def __init__(
            self, _type: str = None, version: int = 0,
            spec_version: str = None, expires: datetime = None
        ) -> None:
        # TODO: How much init magic do we want?

        self._type = _type
        self.spec_version = spec_version

        # We always intend times to be UTC
        # NOTE: we could do this with datetime.fromisoformat() but that is not
        # available in Python 2.7's datetime
        # NOTE: Store as datetime object for convenient handling, use 'expires'
        # property to get the TUF metadata format representation
        self.__expiration = iso8601.parse_date(expires).replace(tzinfo=None)

        if version < 0:
            raise ValueError(f'version must be < 0, got {version}')
        self.version = version

    @property
    def signed_bytes(self) -> bytes:
        return encode_canonical(self.as_dict()).encode('UTF-8')

    @property
    def expires(self) -> str:
        """The expiration property in TUF metadata format."""
        return self.__expiration.isoformat() + 'Z'

    def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
        self.__expiration = self.__expiration + delta

    def bump_version(self) -> None:
        self.version += 1

    def as_dict(self) -> JsonDict:
        # NOTE: The classes should be the single source of truth about metadata
        # let's define the dict representation here and not in some dubious
        # build_dict_conforming_to_schema
        return {
            '_type': self._type,
            'version': self.version,
            'spec_version': self.spec_version,
            'expires': self.expires
        }

    @classmethod
    def read_from_json(
            cls, filename: str,
            storage_backend: Optional[StorageBackendInterface] = None
            ) -> Metadata:
        signable = load_json_file(filename, storage_backend)

        # FIXME: It feels dirty to access signable["signed"]["version"] here in
        # order to do this check, and also a bit random (there are likely other
        # things to check), but later we don't have the filename anymore. If we
        # want to stick to the check, which seems reasonable, we should maybe
        # think of a better place.
        _, fn_prefix = _strip_version_number(filename, True)
        if fn_prefix and fn_prefix != signable['signed']['version']:
            raise ValueError(
                f'version filename prefix ({fn_prefix}) must align with '
                f'version in metadata ({signable["signed"]["version"]}).')

        return Metadata(
            signed=cls(**signable['signed']),
            signatures=signable['signatures'])


class Timestamp(Signed):
    def __init__(self, meta: JsonDict = None, **kwargs) -> None:
        super().__init__(**kwargs)
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        self.meta = meta

    def as_dict(self) -> JsonDict:
        json_dict = super().as_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict

    # Update metadata about the snapshot metadata.
    def update(self, version: int, length: int, hashes: JsonDict) -> None:
        self.meta['snapshot.json'] = {
            'version': version,
            'length': length,
            'hashes': hashes
        }


class Snapshot(Signed):
    def __init__(self, meta: JsonDict = None, **kwargs) -> None:
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        super().__init__(**kwargs)
        self.meta = meta

    def as_dict(self) -> JsonDict:
        json_dict = super().as_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict

    # Add or update metadata about the targets metadata.
    def update(
            self, rolename: str, version: int, length: Optional[int] = None,
            hashes: Optional[JsonDict] = None) -> None:
        metadata_fn = f'{rolename}.json'

        self.meta[metadata_fn] = {'version': version}
        if length is not None:
            self.meta[metadata_fn]['length'] = length

        if hashes is not None:
            self.meta[metadata_fn]['hashes'] = hashes


class Targets(Signed):
    def __init__(
            self, targets: JsonDict = None, delegations: JsonDict = None,
            **kwargs) -> None:
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        super().__init__(**kwargs)
        self.targets = targets
        self.delegations = delegations

    def as_dict(self) -> JsonDict:
        json_dict = super().as_dict()
        json_dict.update({
            'targets': self.targets,
            'delegations': self.delegations,
        })
        return json_dict

    # Add or update metadata about the target.
    def update(self, filename: str, fileinfo: JsonDict) -> None:
        self.targets[filename] = fileinfo
