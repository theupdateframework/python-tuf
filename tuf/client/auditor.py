#!/usr/bin/env python

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  auditor.py

<Author>
  Marina Moore <mnm678@gmail.com>
<Started>
  January 28, 2021
<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.
<Purpose>
  'auditor.py' provides an implementation of an auditor for
  snapshot merkle metadata.

"""

import tuf
import tuf.download
import tuf.formats
import tuf.client.updater

import securesystemslib.hash



class Auditor(object):
  """
  <Purpose>
    Provide a class that downloads and verifies snapshot merkle metadata
    from a repository.

  <Arguments>
    repository_name:
      Name of the repository to be audited

    repository_mirrors:
      Dictionary holding repository mirror information, conformant to
      `tuf.formats.MIRRORDICT_SCHEMA`.

  <Exceptions>
    securesystemslib.exceptions.FormatError:
      If the arguments are improperly formatted.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  def __init__(self, repository_name, repository_mirrors):
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)
    tuf.formats.MIRRORDICT_SCHEMA.check_match(repository_mirrors)

    self.repository_name = repository_name
    self.mirrors = repository_mirrors

    # Create a dictionary to store current version information
    # for all targets metadata
    self.version_info = {}

    # Keep track of the last timestamp version number checked
    self.last_version_verified = 0

    # Updater will be used to update top-level metadata
    self.updater = tuf.client.updater.Updater(repository_name, repository_mirrors)


  def verify(self):
    # download most recent top-level metadata, determine current timestamp key
    self.updater.refresh()

    cur_timestamp_keys = self.updater.metadata['current']['root']['roles']['timestamp']['keyids']

    # Download all trees since last_version_verified that use cur_timestamp_key

    next_version = self.last_version_verified + 1
    version_exists = True

    while(version_exists):
      verification_fn = self.updater.signable_verification

      # Attempt to download this version of timestamp. If it does not exist,
      # break out of the loop
      timestamp = self.updater.download_metadata_version_if_exists("timestamp",
          next_version, verification_fn,
          tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH)

      if not timestamp:
        version_exists = False
        break


      # Compare with the current timestamp keys. We only verify any trees
      # that use the current keys for fast forward attack recovery
      # Check if there are the same number of keys, and that the keyids match
      # TODO: Should the auditor also verify older trees?
      if len(timestamp['signatures']) != len(cur_timestamp_keys):
        break

      for s in timestamp['signatures']:
        if s['keyid'] not in cur_timestamp_keys:
          break

      merkle_root = timestamp['signed']['merkle_root']

      # Download and verify Merkle trees

      # First, download snapshot to get a list of nodes
      snapshot = self.updater.download_metadata_version_if_exists("snapshot",
          next_version, verification_fn,
          tuf.settings.DEFAULT_SNAPSHOT_REQUIRED_LENGTH)

      for metadata_filename in snapshot['signed']['meta']:
        # Download the node and verify its path
        versioninfo = self.updater.verify_merkle_path(
            metadata_filename[:-len('.json')], next_version, merkle_root)

        # Have we seen this metadata file before?
        # If yes, compare the version info
        if metadata_filename in self.version_info:
          if self.version_info[metadata_filename] > versioninfo['version']:
            raise tuf.exceptions.RepositoryError('Rollback attack detected' +
                'for ' + metadata_filename + '. Version ' +
                str(versioninfo['version']) + ' is less than ' +
                str(self.version_info[metadata_filename]))

        # Update `version_info` with the latest seen version
        self.version_info[metadata_filename] = versioninfo['version']


      self.last_version_verified = next_version
      next_version = next_version + 1



