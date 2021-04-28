#!/usr/bin/env python

# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Metadata wrapper
"""
import time

from securesystemslib.keys import format_metadata_to_key

from tuf import exceptions, formats
from tuf.api import metadata


class MetadataWrapper:
    """Helper classes extending or adding missing
    functionality to metadata API
    """

    def __init__(self, meta):
        self._meta = meta

    @classmethod
    def from_json_object(cls, raw_data):
        """Loads JSON-formatted TUF metadata from a file object."""
        # Use local scope import to avoid circular import errors
        # pylint: disable=import-outside-toplevel
        from tuf.api.serialization.json import JSONDeserializer

        deserializer = JSONDeserializer()
        meta = deserializer.deserialize(raw_data)
        return cls(meta=meta)

    @classmethod
    def from_json_file(cls, filename):
        """Loads JSON-formatted TUF metadata from a file."""
        meta = metadata.Metadata.from_file(filename)
        return cls(meta=meta)

    @property
    def signed(self):
        """
        TODO
        """
        return self._meta.signed

    @property
    def version(self):
        """
        TODO
        """
        return self._meta.signed.version

    def verify(self, keys, threshold):
        """
        TODO
        """
        verified = 0
        # 1.3. Check signatures
        for key in keys:
            self._meta.verify(key)
            verified += 1

        if verified < threshold:
            raise exceptions.InsufficientKeysError

    def persist(self, filename):
        """
        TODO
        """
        self._meta.to_file(filename)

    def expires(self, reference_time=None):
        """
        TODO
        """
        if reference_time is None:
            expires_timestamp = formats.datetime_to_unix_timestamp(
                self._meta.signed.expires
            )
            reference_time = int(time.time())

        if expires_timestamp < reference_time:
            raise exceptions.ExpiredMetadataError


class RootWrapper(MetadataWrapper):
    """
    TODO
    """

    def keys(self, role):
        """
        TODO
        """
        keys = []
        for keyid in self._meta.signed.roles[role]["keyids"]:
            key_metadata = self._meta.signed.keys[keyid]
            key, dummy = format_metadata_to_key(key_metadata)
            keys.append(key)

        return keys

    def threshold(self, role):
        """
        TODO
        """
        return self._meta.signed.roles[role]["threshold"]


class TimestampWrapper(MetadataWrapper):
    """
    TODO
    """

    @property
    def snapshot(self):
        """
        TODO
        """
        return self._meta.signed.meta["snapshot.json"]


class SnapshotWrapper(MetadataWrapper):
    """
    TODO
    """

    def role(self, name):
        """
        TODO
        """
        return self._meta.signed.meta[name + ".json"]


class TargetsWrapper(MetadataWrapper):
    """
    TODO
    """

    @property
    def targets(self):
        """
        TODO
        """
        return self._meta.signed.targets

    @property
    def delegations(self):
        """
        TODO
        """
        return self._meta.signed.delegations

    def keys(self, role):
        """
        TODO
        """
        keys = []
        for delegation in self._meta.signed.delegations["roles"]:
            if delegation["name"] == role:
                for keyid in delegation["keyids"]:
                    key_metadata = self._meta.signed.delegations["keys"][keyid]
                    key, dummy = format_metadata_to_key(key_metadata)
                    keys.append(key)
            return keys

    def threshold(self, role):
        """
        TODO
        """
        for delegation in self._meta.signed.delegations["roles"]:
            if delegation["name"] == role:
                return delegation["threshold"]

        return None
