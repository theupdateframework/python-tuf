"""TUF role metadata model.

This module provides container classes for TUF role metadata, including methods
to read/serialize/write from and to JSON, perform TUF-compliant metadata
updates, and create and verify signatures.

TODO:
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
from securesystemslib.keys import create_signature, verify_signature
from tuf.repository_lib import (
    _strip_version_number
)

import iso8601
import tuf.formats


# Types

JsonDict = Dict[str, Any]


# Classes.

class Metadata():
    """A container for signed TUF metadata.

      Provides methods to (de-)serialize JSON metadata from and to file
      storage, and to create and verify signatures.

    Attributes:
        signed: A subclass of Signed, which has the actual metadata payload,
            i.e. one of Targets, Snapshot, Timestamp or Root.

        signatures: A list of signatures over the canonical JSON representation
            of the value of the signed attribute::

            [
                {
                    'keyid': '<SIGNING KEY KEYID>',
                    'sig':' '<SIGNATURE HEX REPRESENTATION>'
                },
                ...
            ]

    """
    def __init__(
            self, signed: 'Signed' = None, signatures: list = None) -> None:
        # TODO: How much init magic do we want?
        self.signed = signed
        self.signatures = signatures

    def as_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        return {
            'signatures': self.signatures,
            'signed': self.signed.as_dict()
        }

    def as_json(self, compact: bool = False) -> None:
        """Returns the optionally compacted JSON representation of self. """
        return json.dumps(
                self.as_dict(),
                indent=(None if compact else 1),
                separators=((',', ':') if compact else (',', ': ')),
                sort_keys=True)

    def sign(self, key: JsonDict, append: bool = False) -> JsonDict:
        """Creates signature over 'signed' and assigns it to 'signatures'.

        Arguments:
            key: A securesystemslib-style private key object used for signing.
            append: A boolean indicating if the signature should be appended to
                the list of signatures or replace any existing signatures. The
                default behavior is to replace signatures.

        Raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            A securesystemslib-style signature object.

        """
        signature = create_signature(key, self.signed.signed_bytes)

        if append:
            self.signatures.append(signature)
        else:
            self.signatures = [signature]

        return signature

    def verify(self, key: JsonDict) -> bool:
        """Verifies 'signatures' over 'signed' that match the passed key by id.

        Arguments:
            key: A securesystemslib-style public key object.

        Raises:
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            A boolean indicating if all identified signatures are valid. False
            if no signature was found for the keyid or any of the found
            signatures is invalid.

            FIXME: Is this behavior expected? An alternative approach would be
            to raise an exception if no signature is found for the keyid,
            and/or if more than one sigantures are found for the keyid.

        """
        signatures_for_keyid = list(filter(
                lambda sig: sig['keyid'] == key['keyid'], self.signatures))

        if not signatures_for_keyid:
            return False

        for signature in signatures_for_keyid:
            if not verify_signature(key, signature, self.signed.signed_bytes):
                return False

        return True


    @classmethod
    def read_from_json(
            cls, filename: str,
            storage_backend: Optional[StorageBackendInterface] = None
            ) -> 'Metadata':
        """Loads JSON-formatted TUF metadata from file storage.

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
        """Writes the JSON representation of self to file storage.

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
    """A base class for the signed part of TUF metadata.

    Objects with base class Signed are usually included in a Metadata object
    on the signed attribute. This class provides attributes and methods that
    are common for all TUF metadata types (roles).

    Attributes:
        _type: The metadata type string.
        version: The metadata version number.
        spec_version: The TUF specification version number (semver) the
            metadata format adheres to.
        expires: The metadata expiration datetime object.
        signed_bytes: The UTF-8 encoded canonical JSON representation of self.

    """
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
        return self.__expiration.isoformat() + 'Z'

    def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
        """Increments the expires attribute by the passed timedelta. """
        self.__expiration = self.__expiration + delta

    def bump_version(self) -> None:
        """Increments the metadata version number by 1."""
        self.version += 1

    def as_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
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
        """Loads corresponding JSON-formatted metadata from file storage.

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
            A TUF Metadata object whose signed attribute contains an object
            of this class.

        """
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
    """A container for the signed part of timestamp metadata.

    Attributes:
        meta: A dictionary that contains information about snapshot metadata::

            {
                'snapshot.json': {
                    'version': <SNAPSHOT METADATA VERSION NUMBER>,
                    'length': <SNAPSHOT METADATA FILE SIZE>, // optional
                    'hashes': {
                        '<HASH ALGO 1>': '<SNAPSHOT METADATA FILE HASH 1>',
                        '<HASH ALGO 2>': '<SNAPSHOT METADATA FILE HASH 2>',
                        ...
                    }
                }
            }

    """
    def __init__(self, meta: JsonDict = None, **kwargs) -> None:
        super().__init__(**kwargs)
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        self.meta = meta

    def as_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().as_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict

    def update(self, version: int, length: int, hashes: JsonDict) -> None:
        """Assigns passed info about snapshot metadata to meta dict. """
        self.meta['snapshot.json'] = {
            'version': version,
            'length': length,
            'hashes': hashes
        }


class Snapshot(Signed):
    """A container for the signed part of snapshot metadata.

    Attributes:
        meta: A dictionary that contains information about targets metadata::

            {
                'targets.json': {
                    'version': <TARGETS METADATA VERSION NUMBER>,
                    'length': <TARGETS METADATA FILE SIZE>, // optional
                    'hashes': {
                        '<HASH ALGO 1>': '<TARGETS METADATA FILE HASH 1>',
                        '<HASH ALGO 2>': '<TARGETS METADATA FILE HASH 2>',
                        ...
                    } // optional
                },
                '<DELEGATED TARGETS ROLE 1>.json': {
                    ...
                },
                '<DELEGATED TARGETS ROLE 2>.json': {
                    ...
                },
                ...
            }

    """
    def __init__(self, meta: JsonDict = None, **kwargs) -> None:
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        super().__init__(**kwargs)
        self.meta = meta

    def as_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().as_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict

    # Add or update metadata about the targets metadata.
    def update(
            self, rolename: str, version: int, length: Optional[int] = None,
            hashes: Optional[JsonDict] = None) -> None:
        """Assigns passed (delegated) targets role info to meta dict. """
        metadata_fn = f'{rolename}.json'

        self.meta[metadata_fn] = {'version': version}
        if length is not None:
            self.meta[metadata_fn]['length'] = length

        if hashes is not None:
            self.meta[metadata_fn]['hashes'] = hashes


class Targets(Signed):
    """A container for the signed part of targets metadata.

    Attributes:
        targets: A dictionary that contains information about target files::

            {
                '<TARGET FILE NAME>': {
                    'length': <TARGET FILE SIZE>,
                    'hashes': {
                        '<HASH ALGO 1>': '<TARGET FILE HASH 1>',
                        '<HASH ALGO 2>': '<TARGETS FILE HASH 2>',
                        ...
                    },
                    'custom': <CUSTOM OPAQUE DICT> // optional
                },
                ...
            }

        delegations: A dictionary that contains a list of delegated target
            roles and public key store used to verify their metadata
            signatures::

            {
                'keys' : {
                    '<KEYID>': {
                        'keytype': '<KEY TYPE>',
                        'scheme': '<KEY SCHEME>',
                        'keyid_hash_algorithms': [
                            '<HASH ALGO 1>',
                            '<HASH ALGO 2>'
                            ...
                        ],
                        'keyval': {
                            'public': '<PUBLIC KEY HEX REPRESENTATION>'
                        }
                    },
                    ...
                },
                'roles': [
                    {
                        'name': '<ROLENAME>',
                        'keyids': ['<SIGNING KEY KEYID>', ...],
                        'threshold': <SIGNATURE THRESHOLD>,
                        'terminating': <TERMINATING BOOLEAN>,
                        'path_hash_prefixes': ['<HEX DIGEST>', ... ], // or
                        'paths' : ['PATHPATTERN', ... ],
                    },
                ...
                ]
            }

    """
    def __init__(
            self, targets: JsonDict = None, delegations: JsonDict = None,
            **kwargs) -> None:
        # TODO: How much init magic do we want?
        # TODO: Is there merit in creating classes for dict fields?
        super().__init__(**kwargs)
        self.targets = targets
        self.delegations = delegations

    def as_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().as_dict()
        json_dict.update({
            'targets': self.targets,
            'delegations': self.delegations,
        })
        return json_dict

    # Add or update metadata about the target.
    def update(self, filename: str, fileinfo: JsonDict) -> None:
        """Assigns passed target file info to meta dict. """
        self.targets[filename] = fileinfo
