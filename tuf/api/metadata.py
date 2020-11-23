"""TUF role metadata model.

This module provides container classes for TUF role metadata, including methods
to read/serialize/write from and to JSON, perform TUF-compliant metadata
updates, and create and verify signatures.

"""
# Imports
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import json
import tempfile

from securesystemslib.formats import encode_canonical
from securesystemslib.util import (
    load_json_file,
    load_json_string,
    persist_temp_file
)
from securesystemslib.storage import StorageBackendInterface
from securesystemslib.keys import create_signature, verify_signature

import tuf.formats
import tuf.exceptions


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
    def __init__(self, signed: 'Signed', signatures: list) -> None:
        self.signed = signed
        self.signatures = signatures


    # Deserialization (factories).
    @classmethod
    def from_dict(cls, metadata: JsonDict) -> 'Metadata':
        """Creates Metadata object from its JSON/dict representation.

        Calls 'from_dict' for any complex metadata attribute represented by a
        class also that has a 'from_dict' factory method. (Currently this is
        only the signed attribute.)

        Arguments:
            metadata: TUF metadata in JSON/dict representation, as e.g.
            returned by 'json.loads'.

        Raises:
            KeyError: The metadata dict format is invalid.
            ValueError: The metadata has an unrecognized signed._type field.

        Returns:
            A TUF Metadata object.

        """
        # Dispatch to contained metadata class on metadata _type field.
        _type = metadata['signed']['_type']

        if _type == 'targets':
            inner_cls = Targets
        elif _type == 'snapshot':
            inner_cls = Snapshot
        elif _type == 'timestamp':
            inner_cls = Timestamp
        elif _type == 'root':
            inner_cls = Root
        else:
            raise ValueError(f'unrecognized metadata type "{_type}"')

        # NOTE: If Signature becomes a class, we should iterate over
        # metadata['signatures'], call Signature.from_dict for each item, and
        # pass a list of Signature objects to the Metadata constructor intead.
        return cls(
                signed=inner_cls.from_dict(metadata['signed']),
                signatures=metadata['signatures'])


    @classmethod
    def from_json(cls, metadata_json: str) -> 'Metadata':
        """Loads JSON-formatted TUF metadata from a string.

        Arguments:
            metadata_json: TUF metadata in JSON-string representation.

        Raises:
            securesystemslib.exceptions.Error, ValueError, KeyError: The
                metadata cannot be parsed.

        Returns:
            A TUF Metadata object.

        """
        return cls.from_dict(load_json_string(metadata_json))


    @classmethod
    def from_json_file(
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
            securesystemslib.exceptions.Error, ValueError, KeyError: The
                metadata cannot be parsed.

        Returns:
            A TUF Metadata object.

        """
        return cls.from_dict(load_json_file(filename, storage_backend))


    # Serialization.
    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        return {
            'signatures': self.signatures,
            'signed': self.signed.to_dict()
        }


    def to_json(self, compact: bool = False) -> None:
        """Returns the optionally compacted JSON representation of self. """
        return json.dumps(
                self.to_dict(),
                indent=(None if compact else 1),
                separators=((',', ':') if compact else (',', ': ')),
                sort_keys=True)


    def to_json_file(
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
        with tempfile.TemporaryFile() as temp_file:
            temp_file.write(self.to_json(compact).encode('utf-8'))
            persist_temp_file(temp_file, filename, storage_backend)


    # Signatures.
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
        signature = create_signature(key, self.signed.to_canonical_bytes())

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
            # TODO: Revise exception taxonomy
            tuf.exceptions.Error: None or multiple signatures found for key.
            securesystemslib.exceptions.FormatError: Key argument is malformed.
            securesystemslib.exceptions.CryptoError, \
                    securesystemslib.exceptions.UnsupportedAlgorithmError:
                Signing errors.

        Returns:
            A boolean indicating if the signature is valid for the passed key.

        """
        signatures_for_keyid = list(filter(
                lambda sig: sig['keyid'] == key['keyid'], self.signatures))

        if not signatures_for_keyid:
            raise tuf.exceptions.Error(
                    f'no signature for key {key["keyid"]}.')

        if len(signatures_for_keyid) > 1:
            raise tuf.exceptions.Error(
                    f'{len(signatures_for_keyid)} signatures for key '
                    f'{key["keyid"]}, not sure which one to verify.')

        return verify_signature(
            key, signatures_for_keyid[0],
            self.signed.to_canonical_bytes())



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


    """
    # NOTE: Signed is a stupid name, because this might not be signed yet, but
    # we keep it to match spec terminology (I often refer to this as "payload",
    # or "inner metadata")

    def __init__(
            self, _type: str, version: int, spec_version: str,
            expires: datetime) -> None:

        self._type = _type
        self.version = version
        self.spec_version = spec_version
        self.expires = expires

        # TODO: Should we separate data validation from constructor?
        if version < 0:
            raise ValueError(f'version must be < 0, got {version}')
        self.version = version


    # Deserialization (factories).
    @classmethod
    def from_dict(cls, signed_dict: JsonDict) -> 'Signed':
        """Creates Signed object from its JSON/dict representation. """

        # Convert 'expires' TUF metadata string to a datetime object, which is
        # what the constructor expects and what we store. The inverse operation
        # is implemented in 'to_dict'.
        signed_dict['expires'] = tuf.formats.expiry_string_to_datetime(
                signed_dict['expires'])
        # NOTE: We write the converted 'expires' back into 'signed_dict' above
        # so that we can pass it to the constructor as  '**signed_dict' below,
        # along with other fields that belong to Signed subclasses.
        # Any 'from_dict'(-like) conversions of fields that correspond to a
        # subclass should be performed in the 'from_dict' method of that
        # subclass and also be written back into 'signed_dict' before calling
        # super().from_dict.

        # NOTE: cls might be a subclass of Signed, if 'from_dict' was called on
        # that subclass (see e.g. Metadata.from_dict).
        return cls(**signed_dict)


    # Serialization.
    def to_canonical_bytes(self) -> bytes:
        """Returns the UTF-8 encoded canonical JSON representation of self. """
        return encode_canonical(self.to_dict()).encode('UTF-8')


    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        return {
            '_type': self._type,
            'version': self.version,
            'spec_version': self.spec_version,
            'expires': self.expires.isoformat() + 'Z'
        }


    # Modification.
    def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
        """Increments the expires attribute by the passed timedelta. """
        self.expires += delta


    def bump_version(self) -> None:
        """Increments the metadata version number by 1."""
        self.version += 1


class Root(Signed):
    """A container for the signed part of root metadata.

    Attributes:
        consistent_snapshot: A boolean indicating whether the repository
            supports consistent snapshots.
        keys: A dictionary that contains a public key store used to verify
            top level roles metadata signatures::
            {
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
        roles: A dictionary that contains a list of signing keyids and
            a signature threshold for each top level role::
            {
                '<ROLE>': {
                    'keyids': ['<SIGNING KEY KEYID>', ...],
                    'threshold': <SIGNATURE THRESHOLD>,
                },
                ...
            }

    """
    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
    # pylint: disable=too-many-arguments
    def __init__(
            self, _type: str, version: int, spec_version: str,
            expires: datetime, consistent_snapshot: bool,
            keys: JsonDict, roles: JsonDict) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add classes for keys and roles
        self.consistent_snapshot = consistent_snapshot
        self.keys = keys
        self.roles = roles


    # Serialization.
    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().to_dict()
        json_dict.update({
            'consistent_snapshot': self.consistent_snapshot,
            'keys': self.keys,
            'roles': self.roles
        })
        return json_dict


    # Update key for a role.
    def add_key(self, role: str, keyid: str, key_metadata: JsonDict) -> None:
        """Adds new key for 'role' and updates the key store. """
        if keyid not in self.roles[role]['keyids']:
            self.roles[role]['keyids'].append(keyid)
            self.keys[keyid] = key_metadata


    # Remove key for a role.
    def remove_key(self, role: str, keyid: str) -> None:
        """Removes key for 'role' and updates the key store. """
        if keyid in self.roles[role]['keyids']:
            self.roles[role]['keyids'].remove(keyid)
            for keyinfo in self.roles.values():
                if keyid in keyinfo['keyids']:
                    return

            del self.keys[keyid]




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
    def __init__(
            self, _type: str, version: int, spec_version: str,
            expires: datetime, meta: JsonDict) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.meta = meta


    # Serialization.
    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().to_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict


    # Modification.
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
    def __init__(
            self, _type: str, version: int, spec_version: str,
            expires: datetime, meta: JsonDict) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.meta = meta

    # Serialization.
    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().to_dict()
        json_dict.update({
            'meta': self.meta
        })
        return json_dict


    # Modification.
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
    # TODO: determine an appropriate value for max-args and fix places where
    # we violate that. This __init__ function takes 7 arguments, whereas the
    # default max-args value for pylint is 5
    # pylint: disable=too-many-arguments
    def __init__(
            self, _type: str, version: int, spec_version: str,
            expires: datetime, targets: JsonDict, delegations: JsonDict
            ) -> None:
        super().__init__(_type, version, spec_version, expires)
        # TODO: Add class for meta
        self.targets = targets
        self.delegations = delegations


    # Serialization.
    def to_dict(self) -> JsonDict:
        """Returns the JSON-serializable dictionary representation of self. """
        json_dict = super().to_dict()
        json_dict.update({
            'targets': self.targets,
            'delegations': self.delegations,
        })
        return json_dict

    # Modification.
    def update(self, filename: str, fileinfo: JsonDict) -> None:
        """Assigns passed target file info to meta dict. """
        self.targets[filename] = fileinfo
