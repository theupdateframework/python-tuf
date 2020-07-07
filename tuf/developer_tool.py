#!/usr/bin/env python

# Copyright 2014 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  developer_tool.py

<Authors>
  Santiago Torres <torresariass@gmail.com>
  Zane Fisher <zanefisher@gmail.com>

  Based on the work done for 'repository_tool.py' by Vladimir Diaz.

<Started>
  January 22, 2014.

<Copyright>
  See LICENCE-MIT OR LICENCE for licensing information.

<Purpose>
  See 'tuf/README-developer-tools.md' for a complete guide on using
  'developer_tool.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

import os
import errno
import logging
import shutil
import tempfile
import json

import tuf
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.log
import tuf.repository_lib as repo_lib
import tuf.repository_tool

import securesystemslib
import securesystemslib.util
import securesystemslib.keys

import six

from tuf.repository_tool import Targets
from tuf.repository_lib import _check_role_keys
from tuf.repository_lib import _metadata_is_partially_loaded


# Copy API
# pylint: disable=unused-import

# Copy generic repository API functions to be used via `developer_tool`
from tuf.repository_lib import (
    generate_targets_metadata,
    create_tuf_client_directory,
    disable_console_log_messages)

# Copy key-related API functions to be used via `developer_tool`
from tuf.repository_lib import (
    import_rsa_privatekey_from_file)

from securesystemslib.keys import (
    format_keyval_to_metadata)

from securesystemslib.interface import (
    generate_and_write_rsa_keypair,
    generate_and_write_ed25519_keypair,
    import_rsa_publickey_from_file,
    import_ed25519_publickey_from_file,
    import_ed25519_privatekey_from_file)


# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger(__name__)

# The extension of TUF metadata.
from tuf.repository_lib import METADATA_EXTENSION as METADATA_EXTENSION

# Project configuration filename. This file is intended to hold all of the
# supporting information about the project that's not contained in a usual
# TUF metadata file. 'project.cfg' consists of the following fields:
#
#   targets_location:   the location of the targets folder.
#
#   prefix:             the directory location to prepend to the metadata so it
#                       matches the metadata signed in the repository.
#
#   metadata_location:  the location of the metadata files.
#
#   threshold:          the threshold for this project object, it is fixed to
#                       one in the current version.
#
#   public_keys:        a list of the public keys used to verify the metadata
#                       in this project.
#
#   layout_type:        a field describing the directory layout:
#
#                         repo-like: matches the layout of the repository tool.
#                                    the targets and metadata folders are
#                                    located under a common directory for the
#                                    project.
#
#                         flat:      the targets directory and the
#                                    metadata directory are located in different
#                                    paths.
#
#   project_name:       The name of the current project, this value is used to
#                       match the resulting filename with the one in upstream.
PROJECT_FILENAME = 'project.cfg'

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
from tuf.repository_tool import METADATA_DIRECTORY_NAME
from tuf.repository_tool import TARGETS_DIRECTORY_NAME


class Project(Targets):
  """
  <Purpose>
    Simplify the publishing process of third-party projects by handling all of
    the bookkeeping, signature handling, and integrity checks of delegated TUF
    metadata.  'repository_tool.py' is responsible for publishing and
    maintaining metadata of the top-level roles, and 'developer_tool.py' is
    used by projects that have been delegated responsibility for a delegated
    projects role.  Metadata created by this module may then be added to other
    metadata available in a TUF repository.

    Project() is the representation of a project's metadata file(s), with the
    ability to modify this data in an OOP manner.  Project owners do not have to
    manually verify that metadata files are properly formatted or that they
    contain valid data.

  <Arguments>
    project_name:
      The name of the metadata file as it should be named in the upstream
      repository.

    metadata_directory:
      The metadata sub-directory contains the metadata file(s) of this project,
      including any of its delegated roles.

    targets_directory:
      The targets sub-directory contains the project's target files that are
      downloaded by clients and are referenced in its metadata.  The hashes and
      file lengths are listed in Metadata files so that they are securely
      downloaded.  Metadata files are similarly referenced in the top-level
      metadata.

    file_prefix:
      The path string that will be prepended to the generated metadata
      (e.g., targets/foo -> targets/prefix/foo) so that it matches the actual
      targets location in the upstream repository.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted.

  <Side Effects>
    Creates a project Targets role object, with the same object attributes of
    the top-level targets role.

  <Returns>
    None.
  """

  def __init__(self, project_name, metadata_directory, targets_directory,
      file_prefix, repository_name='default'):

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.  Raise
    # 'securesystemslib.exceptions.FormatError' if any are improperly
    # formatted.
    securesystemslib.formats.NAME_SCHEMA.check_match(project_name)
    securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)
    securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)
    securesystemslib.formats.ANY_STRING_SCHEMA.check_match(file_prefix)
    securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

    self.metadata_directory = metadata_directory
    self.targets_directory = targets_directory
    self.project_name = project_name
    self.prefix = file_prefix
    self.repository_name = repository_name

    # Layout type defaults to "flat" unless explicitly specified in
    # create_new_project().
    self.layout_type = 'flat'

    # Set the top-level Targets object.  Set the rolename to be the project's
    # name.
    super(Project, self).__init__(self.targets_directory, project_name)





  def write(self, write_partial=False):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files.
      write() raises an exception if any of the role metadata to be written to
      disk is invalid, such as an insufficient threshold of signatures, missing
      private keys, etc.

    <Arguments>
      write_partial:
        A boolean indicating whether partial metadata should be written to
        disk.  Partial metadata may be written to allow multiple maintainters
        to independently sign and update role metadata.  write() raises an
        exception if a metadata role cannot be written due to not having enough
        signatures.

    <Exceptions>
      securesystemslib.exceptions.Error, if any of the project roles do not
      have a minimum threshold of signatures.

    <Side Effects>
      Creates metadata files in the project's metadata directory.

    <Returns>
      None.
    """

    # Does 'write_partial' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'securesystemslib.exceptions.FormatError' if any are improperly formatted.
    securesystemslib.formats.BOOLEAN_SCHEMA.check_match(write_partial)

    # At this point the tuf.keydb and tuf.roledb stores must be fully
    # populated, otherwise write() throwns a 'tuf.Repository' exception if
    # any of the project roles are missing signatures, keys, etc.

    # Write the metadata files of all the delegated roles of the project.
    delegated_rolenames = tuf.roledb.get_delegated_rolenames(self.project_name,
        self.repository_name)

    for delegated_rolename in delegated_rolenames:
      delegated_filename = os.path.join(self.metadata_directory,
          delegated_rolename + METADATA_EXTENSION)

      # Ensure the parent directories of 'metadata_filepath' exist, otherwise an
      # IO exception is raised if 'metadata_filepath' is written to a
      # sub-directory.
      securesystemslib.util.ensure_parent_dir(delegated_filename)

      _generate_and_write_metadata(delegated_rolename, delegated_filename,
          write_partial, self.targets_directory, prefix=self.prefix,
          repository_name=self.repository_name)


    # Generate the 'project_name' metadata file.
    targets_filename = self.project_name + METADATA_EXTENSION
    targets_filename = os.path.join(self.metadata_directory, targets_filename)
    junk, targets_filename = _generate_and_write_metadata(self.project_name,
        targets_filename, write_partial, self.targets_directory,
        prefix=self.prefix, repository_name=self.repository_name)

    # Save configuration information that is not stored in the project's
    # metadata
    _save_project_configuration(self.metadata_directory,
        self.targets_directory, self.keys, self.prefix, self.threshold,
        self.layout_type, self.project_name)





  def add_verification_key(self, key, expires=None):
    """
      <Purpose>
        Function as a thin wrapper call for the project._targets call
        with the same name. This wrapper is only for usability purposes.

      <Arguments>
        key:
          The role key to be added, conformant to
          'securesystemslib.formats.ANYKEY_SCHEMA'.  Adding a public key to a
          role means that its corresponding private key must generate and add
          its signture to the role.

      <Exceptions>
        securesystemslib.exceptions.FormatError, if the 'key' argument is
        improperly formatted.

        securesystemslib.exceptions.Error, if the project already contains a key.

      <Side Effects>
        The role's entries in 'tuf.keydb.py' and 'tuf.roledb.py' are updated.

      <Returns>
        None
    """

    # Verify that this role does not already contain a key.  The parent project
    # role is restricted to one key.  Any of its delegated roles may have
    # more than one key.
    # TODO: Add condition check for the requirement stated above.
    if len(self.keys) > 0:
      raise securesystemslib.exceptions.Error("This project already contains a key.")

    super(Project, self).add_verification_key(key, expires)





  def status(self):
    """
    <Purpose>
      Determine the status of the project, including its delegated roles.
      status() checks if each role provides sufficient public keys, signatures,
      and that a valid metadata file is generated if write() were to be called.
      Metadata files are temporarily written to check that proper metadata files
      is written, where file hashes and lengths are calculated and referenced
      by the project.  status() does not do a simple check for number of
      threshold keys and signatures.

    <Arguments>
      None.

    <Exceptions>
      securesystemslib.exceptions.Error, if the project, or any of its
      delegated roles, do not have a minimum threshold of signatures.

    <Side Effects>
      Generates and writes temporary metadata files.

    <Returns>
      None.
    """

    temp_project_directory = None

    try:
      temp_project_directory = tempfile.mkdtemp()

      metadata_directory = os.path.join(temp_project_directory, 'metadata')
      targets_directory = self.targets_directory

      os.makedirs(metadata_directory)

      # TODO: We should do the schema check.
      filenames = {}
      filenames['targets'] = os.path.join(metadata_directory, self.project_name)

      # Delegated roles.
      delegated_roles = tuf.roledb.get_delegated_rolenames(self.project_name,
          self.repository_name)
      insufficient_keys = []
      insufficient_signatures = []

      for delegated_role in delegated_roles:
        try:
          _check_role_keys(delegated_role, self.repository_name)

        except tuf.exceptions.InsufficientKeysError:
          insufficient_keys.append(delegated_role)
          continue

        try:
          signable = _generate_and_write_metadata(delegated_role,
              filenames['targets'], False, targets_directory, False,
              repository_name=self.repository_name)
          self._log_status(delegated_role, signable[0], self.repository_name)

        except securesystemslib.exceptions.Error:
          insufficient_signatures.append(delegated_role)

      if len(insufficient_keys):
        message = 'Delegated roles with insufficient keys: ' +\
          repr(insufficient_keys)
        logger.info(message)
        return

      if len(insufficient_signatures):
        message = 'Delegated roles with insufficient signatures: ' +\
          repr(insufficient_signatures)
        logger.info(message)
        return

      # Targets role.
      try:
        _check_role_keys(self.rolename, self.repository_name)

      except tuf.exceptions.InsufficientKeysError as e:
        logger.info(str(e))
        return

      try:
        signable, junk =  _generate_and_write_metadata(self.project_name,
            filenames['targets'], False, targets_directory, metadata_directory,
            self.repository_name)
        self._log_status(self.project_name, signable, self.repository_name)

      except tuf.exceptions.UnsignedMetadataError as e:
        # This error is raised if the metadata has insufficient signatures to
        # meet the threshold.
        self._log_status(self.project_name, e.signable, self.repository_name)
        return

    finally:
      shutil.rmtree(temp_project_directory, ignore_errors=True)





  def _log_status(self, rolename, signable, repository_name):
    """
    Non-public function prints the number of (good/threshold) signatures of
    'rolename'.
    """

    status = tuf.sig.get_signature_status(signable, rolename, repository_name)

    message = repr(rolename) + ' role contains ' +\
      repr(len(status['good_sigs'])) + ' / ' + repr(status['threshold']) +\
      ' signatures.'
    logger.info(message)





def _generate_and_write_metadata(rolename, metadata_filename, write_partial,
    targets_directory, prefix='', repository_name='default'):
  """
    Non-public function that can generate and write the metadata of the
    specified 'rolename'.  It also increments version numbers if:

    1.  write_partial==True and the metadata is the first to be written.

    2.  write_partial=False (i.e., write()), the metadata was not loaded as
        partially written, and a write_partial is not needed.
  """

  metadata = None

  # Retrieve the roleinfo of 'rolename' to extract the needed metadata
  # attributes, such as version number, expiration, etc.
  roleinfo = tuf.roledb.get_roleinfo(rolename, repository_name)

  metadata = generate_targets_metadata(targets_directory, roleinfo['paths'],
      roleinfo['version'], roleinfo['expires'], roleinfo['delegations'],
      False)

  # Prepend the prefix to the project's filepath to avoid signature errors in
  # upstream.
  for element in list(metadata['targets']):
    junk, relative_target = os.path.split(element)
    prefixed_path = os.path.join(prefix, relative_target)
    metadata['targets'][prefixed_path] = metadata['targets'][element]
    if prefix != '':
      del(metadata['targets'][element])

  signable = repo_lib.sign_metadata(metadata, roleinfo['signing_keyids'],
      metadata_filename, repository_name)

  # Check if the version number of 'rolename' may be automatically incremented,
  # depending on whether if partial metadata is loaded or if the metadata is
  # written with write() / write_partial().
  # Increment the version number if this is the first partial write.
  if write_partial:
    temp_signable = repo_lib.sign_metadata(metadata, [], metadata_filename,
        repository_name)
    temp_signable['signatures'].extend(roleinfo['signatures'])
    status = tuf.sig.get_signature_status(temp_signable, rolename,
        repository_name)
    if len(status['good_sigs']) == 0:
      metadata['version'] = metadata['version'] + 1
      signable = repo_lib.sign_metadata(metadata, roleinfo['signing_keyids'],
          metadata_filename, repository_name)

  # non-partial write()
  else:
    if tuf.sig.verify(signable, rolename, repository_name):
      metadata['version'] = metadata['version'] + 1
      signable = repo_lib.sign_metadata(metadata, roleinfo['signing_keyids'],
          metadata_filename, repository_name)

  # Write the metadata to file if contains a threshold of signatures.
  signable['signatures'].extend(roleinfo['signatures'])

  if tuf.sig.verify(signable, rolename, repository_name) or write_partial:
    repo_lib._remove_invalid_and_duplicate_signatures(signable, repository_name)
    storage_backend = securesystemslib.storage.FilesystemBackend()
    filename = repo_lib.write_metadata_file(signable, metadata_filename,
        metadata['version'], False, storage_backend)

  # 'signable' contains an invalid threshold of signatures.
  else:
    message = 'Not enough signatures for ' + repr(metadata_filename)
    raise securesystemslib.exceptions.Error(message, signable)

  return signable, filename




def create_new_project(project_name, metadata_directory,
    location_in_repository = '', targets_directory=None, key=None,
    repository_name='default'):
  """
  <Purpose>
    Create a new project object, instantiate barebones metadata for the
    targets, and return a blank project object.  On disk, create_new_project()
    only creates the directories needed to hold the metadata and targets files.
    The project object returned can be directly modified to meet the designer's
    criteria and then written using the method project.write().

    The project name provided is the one that will be added to the resulting
    metadata file as it should be named in upstream.

  <Arguments>
    project_name:
      The name of the project as it should be called in upstream. For example,
      targets/unclaimed/django should have its project_name set to "django"

    metadata_directory:
      The directory that will eventually hold the metadata and target files of
      the project.

    location_in_repository:
      An optional argument to hold the "prefix" or the expected location for
      the project files in the "upstream" repository. This value is only
      used to sign metadata in a way that it matches the future location
      of the files.

      For example, targets/unclaimed/django should have its project name set to
      "targets/unclaimed"

    targets_directory:
      An optional argument to point the targets directory somewhere else than
      the metadata directory if, for example, a project structure already
      exists and the user does not want to move it.

    key:
      The public key to verify the project's metadata. Projects can only
      handle one key with a threshold of one. If a project were to modify it's
      key it should be removed and updated.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if the arguments are improperly
    formatted or if the public key is not a valid one (if it's not none.)

    OSError, if the filepaths provided do not have write permissions.

  <Side Effects>
    The 'metadata_directory' and 'targets_directory'  directories are created
    if they do not exist.

  <Returns>
    A 'tuf.developer_tool.Project' object.
  """

  # Does 'metadata_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)

  # Do the same for the location in the repo and the project name, we must
  # ensure they are valid pathnames.
  securesystemslib.formats.NAME_SCHEMA.check_match(project_name)
  securesystemslib.formats.ANY_STRING_SCHEMA.check_match(location_in_repository)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # for the targets directory we do the same, but first, let's find out what
  # layout the user needs, layout_type is a variable that is usually set to
  # 1, which means "flat" (i.e. the cfg file is where the metadata folder is
  # located), with a two, the cfg file goes to the "metadata" folder, and a
  # new metadata folder is created inside the tree, to separate targets and
  # metadata.
  layout_type = 'flat'
  if targets_directory is None:
    targets_directory = os.path.join(metadata_directory, TARGETS_DIRECTORY_NAME)
    metadata_directory = \
        os.path.join(metadata_directory, METADATA_DIRECTORY_NAME)
    layout_type = 'repo-like'

  if targets_directory is not None:
    securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)

  if key is not None:
    securesystemslib.formats.KEY_SCHEMA.check_match(key)

  # Set the metadata and targets directories.  These directories
  # are created if they do not exist.
  metadata_directory = os.path.abspath(metadata_directory)
  targets_directory = os.path.abspath(targets_directory)

  # Try to create the metadata directory that will hold all of the metadata
  # files, such as 'root.txt' and 'release.txt'.
  try:
    message = 'Creating ' + repr(metadata_directory)
    logger.info(message)
    os.makedirs(metadata_directory)

  # 'OSError' raised if the leaf directory already exists or cannot be created.
  # Check for case where 'repository_directory' has already been created.
  except OSError as e:
    if e.errno == errno.EEXIST:
      # Should check if we have write permissions here.
      pass

    # Testing of non-errno.EEXIST exceptions have been verified on all
    # supported # OSs.  An unexpected exception (the '/' directory exists,
    # rather than disallowed path) is possible on Travis, so the '#pragma: no
    # branch' below is included to prevent coverage failure.
    else: #pragma: no branch
      raise

  # Try to create the targets directory that will hold all of the target files.
  try:
    message = 'Creating ' + repr(targets_directory)
    logger.info(message)
    os.mkdir(targets_directory)

  except OSError as e:
    if e.errno == errno.EEXIST:
      pass

    else:
      raise

  # Create the bare bones project object, where project role contains default
  # values (e.g., threshold of 1, expires 1 year into the future, etc.)
  project = Project(project_name, metadata_directory, targets_directory,
      location_in_repository, repository_name)

  # Add 'key' to the project.
  # TODO: Add check for expected number of keys for the project (must be 1) and
  # its delegated roles (may be greater than one.)
  if key is not None:
    project.add_verification_key(key)

  # Save the layout information.
  project.layout_type = layout_type

  return project






def _save_project_configuration(metadata_directory, targets_directory,
    public_keys, prefix, threshold, layout_type, project_name):
  """
  <Purpose>
    Persist the project's information to a file. The saved project information
    can later be loaded with Project.load_project().

  <Arguments>
    metadata_directory:
      Where the project's metadata is located.

    targets_directory:
      The location of the target files for this project.

    public_keys:
      A list containing the public keys for the project role.

    prefix:
      The project's prefix (if any.)

    threshold:
      The threshold value for the project role.

    layout_type:
      The layout type being used by the project, "flat" stands for separated
      targets and metadata directories, "repo-like" emulates the layout used
      by the repository tools

    project_name:
      The name given to the project, this sets the metadata filename so it
      matches the one stored in upstream.

  <Exceptions>
    securesystemslib.exceptions.FormatError are also expected if any of the arguments are malformed.

    OSError may rise if the metadata_directory/project.cfg file exists and
    is non-writeable

  <Side Effects>
    A 'project.cfg' configuration file is created or overwritten.

  <Returns>
    None.
  """

  # Schema check for the arguments.
  securesystemslib.formats.PATH_SCHEMA.check_match(metadata_directory)
  securesystemslib.formats.PATH_SCHEMA.check_match(prefix)
  securesystemslib.formats.PATH_SCHEMA.check_match(targets_directory)
  tuf.formats.RELPATH_SCHEMA.check_match(project_name)

  cfg_file_directory = metadata_directory

  # Check whether the layout type is 'flat' or 'repo-like'.
  # If it is, the .cfg file should be saved in the previous directory.
  if layout_type == 'repo-like':
    cfg_file_directory = os.path.dirname(metadata_directory)
    junk, targets_directory = os.path.split(targets_directory)

  junk, metadata_directory = os.path.split(metadata_directory)

  # Can the file be opened?
  project_filename = os.path.join(cfg_file_directory, PROJECT_FILENAME)

  # Build the fields of the configuration file.
  project_config = {}
  project_config['prefix'] = prefix
  project_config['public_keys'] = {}
  project_config['metadata_location'] = metadata_directory
  project_config['targets_location'] = targets_directory
  project_config['threshold'] = threshold
  project_config['layout_type'] = layout_type
  project_config['project_name'] = project_name

  # Build a dictionary containing the actual keys.
  for key in public_keys:
    key_info = tuf.keydb.get_key(key)
    key_metadata = format_keyval_to_metadata(key_info['keytype'],
        key_info['scheme'], key_info['keyval'])
    project_config['public_keys'][key] = key_metadata

  # Save the actual file.
  with open(project_filename, 'wt') as fp:
    json.dump(project_config, fp)





def load_project(project_directory, prefix='', new_targets_location=None,
    repository_name='default'):
  """
  <Purpose>
    Return a Project object initialized with the contents of the metadata
    files loaded from 'project_directory'.

  <Arguments>
    project_directory:
      The path to the project's metadata and configuration file.

    prefix:
      The prefix for the metadata, if defined.  It will replace the current
      prefix, by first removing the existing one (saved).

    new_targets_location:
      For flat project configurations, project owner might want to reload the
      project with a new location for the target files. This overwrites the
      previous path to search for the target files.

    repository_name:
      The name of the repository.  If not supplied, 'rolename' is added to the
      'default' repository.

  <Exceptions>
    securesystemslib.exceptions.FormatError, if 'project_directory' or any of
    the metadata files are improperly formatted.

  <Side Effects>
    All the metadata files found in the project are loaded and their contents
    stored in a libtuf.Repository object.

  <Returns>
    A tuf.developer_tool.Project object.
  """

  # Does 'repository_directory' have the correct format?
  # Raise 'securesystemslib.exceptions.FormatError' if there is a mismatch.
  securesystemslib.formats.PATH_SCHEMA.check_match(project_directory)
  securesystemslib.formats.NAME_SCHEMA.check_match(repository_name)

  # Do the same for the prefix
  securesystemslib.formats.ANY_STRING_SCHEMA.check_match(prefix)

  # Clear the role and key databases since we are loading in a new project.
  tuf.roledb.clear_roledb(clear_all=True)
  tuf.keydb.clear_keydb(clear_all=True)

  # Locate metadata filepaths and targets filepath.
  project_directory = os.path.abspath(project_directory)

  # Load the cfg file and the project.
  config_filename = os.path.join(project_directory, PROJECT_FILENAME)

  project_configuration = securesystemslib.util.load_json_file(config_filename)
  tuf.formats.PROJECT_CFG_SCHEMA.check_match(project_configuration)

  targets_directory = os.path.join(project_directory,
      project_configuration['targets_location'])

  if project_configuration['layout_type'] == 'flat':
    project_directory, junk = os.path.split(project_directory)
    targets_directory = project_configuration['targets_location']

    if new_targets_location is not None:
      targets_directory = new_targets_location

  metadata_directory = os.path.join(project_directory,
      project_configuration['metadata_location'])

  new_prefix = None

  if prefix != '':
    new_prefix = prefix

  prefix = project_configuration['prefix']

  # Load the project's filename.
  project_name = project_configuration['project_name']
  project_filename = project_name + METADATA_EXTENSION

  # Create a blank project on the target directory.
  project = Project(project_name, metadata_directory, targets_directory, prefix,
      repository_name)

  project.threshold = project_configuration['threshold']
  project.prefix = project_configuration['prefix']
  project.layout_type = project_configuration['layout_type']

  # Traverse the public keys and add them to the project.
  keydict = project_configuration['public_keys']

  for keyid in keydict:
    key, junk = securesystemslib.keys.format_metadata_to_key(keydict[keyid])
    project.add_verification_key(key)

  # Load the project's metadata.
  targets_metadata_path = os.path.join(project_directory, metadata_directory,
      project_filename)
  signable = securesystemslib.util.load_json_file(targets_metadata_path)
  tuf.formats.check_signable_object_format(signable)
  targets_metadata = signable['signed']

  # Remove the prefix from the metadata.
  targets_metadata = _strip_prefix_from_targets_metadata(targets_metadata,
                                            prefix)
  for signature in signable['signatures']:
    project.add_signature(signature)

  # Update roledb.py containing the loaded project attributes.
  roleinfo = tuf.roledb.get_roleinfo(project_name, repository_name)
  roleinfo['signatures'].extend(signable['signatures'])
  roleinfo['version'] = targets_metadata['version']
  roleinfo['paths'] = targets_metadata['targets']
  roleinfo['delegations'] = targets_metadata['delegations']
  roleinfo['partial_loaded'] = False

  # Check if the loaded metadata was partially written and update the
  # flag in 'roledb.py'.
  if _metadata_is_partially_loaded(project_name, signable,
      repository_name=repository_name):
    roleinfo['partial_loaded'] = True

  tuf.roledb.update_roleinfo(project_name, roleinfo, mark_role_as_dirty=False,
      repository_name=repository_name)

  for key_metadata in targets_metadata['delegations']['keys'].values():
    key_object, junk = securesystemslib.keys.format_metadata_to_key(key_metadata)
    tuf.keydb.add_key(key_object, repository_name=repository_name)

  for role in targets_metadata['delegations']['roles']:
    rolename = role['name']
    roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                'threshold': role['threshold'],
                'signing_keyids': [], 'signatures': [], 'partial_loaded':False,
                'delegations': {'keys':{}, 'roles':[]}
                }
    tuf.roledb.add_role(rolename, roleinfo, repository_name=repository_name)

  # Load the delegated metadata and generate their fileinfo.
  targets_objects = {}
  loaded_metadata = [project_name]
  targets_objects[project_name] = project
  metadata_directory = os.path.join(project_directory, metadata_directory)

  if os.path.exists(metadata_directory) and \
                    os.path.isdir(metadata_directory):
    for metadata_role in os.listdir(metadata_directory):
      metadata_path = os.path.join(metadata_directory, metadata_role)
      metadata_name = \
        metadata_path[len(metadata_directory):].lstrip(os.path.sep)

      # Strip the extension.  The roledb does not include an appended '.json'
      # extension for each role.
      if metadata_name.endswith(METADATA_EXTENSION):
        extension_length = len(METADATA_EXTENSION)
        metadata_name = metadata_name[:-extension_length]

      else:
        continue

      if metadata_name in loaded_metadata:
        continue

      signable = None
      signable = securesystemslib.util.load_json_file(metadata_path)

      # Strip the prefix from the local working copy, it will be added again
      # when the targets metadata is written to disk.
      metadata_object = signable['signed']
      metadata_object = _strip_prefix_from_targets_metadata(metadata_object,
                                           prefix)

      roleinfo = tuf.roledb.get_roleinfo(metadata_name, repository_name)
      roleinfo['signatures'].extend(signable['signatures'])
      roleinfo['version'] = metadata_object['version']
      roleinfo['expires'] = metadata_object['expires']
      roleinfo['paths'] = {}

      for filepath, fileinfo in six.iteritems(metadata_object['targets']):
        roleinfo['paths'].update({filepath: fileinfo.get('custom', {})})
      roleinfo['delegations'] = metadata_object['delegations']
      roleinfo['partial_loaded'] = False

      # If the metadata was partially loaded, update the roleinfo flag.
      if _metadata_is_partially_loaded(metadata_name, signable,
          repository_name=repository_name):
        roleinfo['partial_loaded'] = True


      tuf.roledb.update_roleinfo(metadata_name, roleinfo,
          mark_role_as_dirty=False, repository_name=repository_name)

      # Append to list of elements to avoid reloading repeated metadata.
      loaded_metadata.append(metadata_name)

      # Generate the Targets objects of the delegated roles.
      new_targets_object = Targets(targets_directory, metadata_name, roleinfo,
          repository_name=repository_name)
      targets_object = targets_objects[project_name]

      targets_object._delegated_roles[metadata_name] = new_targets_object

      # Add the keys specified in the delegations field of the Targets role.
      for key_metadata in metadata_object['delegations']['keys'].values():
        key_object, junk = securesystemslib.keys.format_metadata_to_key(key_metadata)

        try:
          tuf.keydb.add_key(key_object, repository_name=repository_name)

        except tuf.exceptions.KeyAlreadyExistsError:
          pass

      for role in metadata_object['delegations']['roles']:
        rolename = role['name']
        roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                    'threshold': role['threshold'],
                    'signing_keyids': [], 'signatures': [],
                    'partial_loaded': False,
                    'delegations': {'keys': {},
                                    'roles': []}}
        tuf.roledb.add_role(rolename, roleinfo, repository_name=repository_name)

  if new_prefix:
    project.prefix = new_prefix

  return project





def _strip_prefix_from_targets_metadata(targets_metadata, prefix):
  """
    Non-public method that removes the prefix from each of the target paths in
    'targets_metadata' so they can be used again in compliance with the local
    copies.  The prefix is needed in metadata to match the layout of the remote
    repository.
  """

  unprefixed_targets_metadata = {}

  for targets in targets_metadata['targets'].keys():
    unprefixed_target = os.path.relpath(targets, prefix)
    unprefixed_targets_metadata[unprefixed_target] = \
                            targets_metadata['targets'][targets]
  targets_metadata['targets'] = unprefixed_targets_metadata

  return targets_metadata





if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running 'developer_tool.py' as a standalone module:
  # $ python developer_tool.py
  import doctest
  doctest.testmod()
