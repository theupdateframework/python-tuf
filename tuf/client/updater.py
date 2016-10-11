"""
<Program Name>
  updater.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  July 2012.  Based on a previous version of this module. (VLAD)

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  'updater.py' is intended to be the only TUF module that software update
  systems need to utilize.  It provides a single class representing an
  updater that includes methods to download, install, and verify
  metadata/target files in a secure manner.  Importing 'updater.py' and
  instantiating its main class is all that is required by the client prior
  to a TUF update request.  The importation and instantiation steps allow
  TUF to load all of the required metadata files and set the repository mirror
  information.

  An overview of the update process:

  1. The software update system instructs TUF to check for updates.

  2. TUF downloads and verifies timestamp.json.

  3. If timestamp.json indicates that snapshot.json has changed, TUF downloads
     and verifies snapshot.json.

  4. TUF determines which metadata files listed in snapshot.json differ from
     those described in the last snapshot.json that TUF has seen.  If root.json
     has changed, the update process starts over using the new root.json.

  5. TUF provides the software update system with a list of available files
     according to targets.json.

  6. The software update system instructs TUF to download a specific target
     file.

  7. TUF downloads and verifies the file and then makes the file available to
     the software update system.

<Example Client>

  # The client first imports the 'updater.py' module, the only module the
  # client is required to import.  The client will utilize a single class
  # from this module.
  import tuf.client.updater

  # The only other module the client interacts with is 'tuf.conf'.  The
  # client accesses this module solely to set the repository directory.
  # This directory will hold the files downloaded from a remote repository.
  tuf.conf.repository_directory = 'local-repository'

  # OLD: repository_mirrors format has changed. REWRITE AFTER DESIGN CONFIRM:
    # Next, the client creates a dictionary object containing the repository
    # mirrors.  The client may download content from any one of these mirrors.
    # In the example below, a single mirror named 'mirror1' is defined.  The
    # mirror is located at 'http://localhost:8001', and all of the metadata
    # and targets files can be found in the 'metadata' and 'targets' directory,
    # respectively.  If the client wishes to only download target files from
    # specific directories on the mirror, the 'confined_target_dirs' field
    # should be set.  In the example, the client has chosen '', which is
    # interpreted as no confinement.  In other words, the client can download
    # targets from any directory or subdirectories.  If the client had chosen
    # 'targets1/', they would have been confined to the '/targets/targets1/'
    # directory on the 'http://localhost:8001' mirror. 
    repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
                                      'metadata_path': 'metadata',
                                      'targets_path': 'targets',
                                      'confined_target_dirs': ['']}}

  # The updater may now be instantiated.  The Updater class of 'updater.py'
  # is called with two arguments.  The first argument assigns a name to this
  # particular updater and the second argument the repository mirrors defined
  # above.
  updater = tuf.client.updater.Updater('updater', repository_mirrors)

  # The client next calls the refresh() method to ensure it has the latest
  # copies of the metadata files.
  updater.refresh()

  # The target file information for all the repository targets is determined.
  targets = updater.all_targets()
  
  # Among these targets, determine the ones that have changed since the client's
  # last refresh().  A target is considered updated if it does not exist in
  # 'destination_directory' (current directory) or the target located there has
  # changed.
  destination_directory = '.'
  updated_targets = updater.updated_targets(targets, destination_directory)

  # Lastly, attempt to download each target among those that have changed.
  # The updated target files are saved locally to 'destination_directory'.
  for target in updated_targets:
    updater.download_target(target, destination_directory)
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import errno
import logging
import os
import shutil
import time
import random
import fnmatch

import tuf
import tuf.conf
import tuf.download
import tuf.formats
import tuf.hash
import tuf.keys
import tuf.keydb
import tuf.log
import tuf.mirrors
import tuf.roledb
import tuf.sig
import tuf.util

import six
import iso8601

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.client.updater')

# Disable 'iso8601' logger messages to prevent 'iso8601' from clogging the
# log file.
iso8601_logger = logging.getLogger('iso8601')
iso8601_logger.disabled = True


class Updater(object):
  """
  <Purpose>

  <Updater Attributes>
    self.repositories:
      Dictionary of SingleRepoUpdater objects, indexed by repository name.

    self.pinned_metadata_fname:
      The full filename of pinned.json.

    self.pinned_metadata:
      The contents of pinned.json, delegating namespaces to different
      repositories. This determines which repository/ies to use for which
      target/s.

  <Updater Methods>


  """


  def __init__(self, updater_name):
    """
    <Purpose>

      Constructor.  Instantiating an updater object reads pinned.json into
      memory and instantiates a SingleRepoUpdater object for each repository
      entry in the pinned.json metadata. This causes all the metadata files for
      the files for the top- level roles to be read from disk, including the
      key and role information for the delegated targets of 'targets'.  The
      actual metadata for delegated roles is not loaded in __init__.  The
      metadata for these delegated roles, including nested delegated roles, are
      loaded, updated, and saved to the 'self.metadata' store by the target
      methods, like all_targets() and targets_of_role().

      The initial set of metadata files (critically, root.json) is provided by
      the software update system utilizing TUF.

      There are several requirements to be able to instantiate an updater:

      1.  The pinned.json file is expected to be in the following location:
            {tuf.conf.repository_directory}/metadata/pinned.json
          See TAP 4 at github.com/theupdateframework/taps for more information.

      2.  For each repository, the following directories must already exist
          locally:
            {tuf.conf.repository_directory}/metadata/<repository_name>/current
            {tuf.conf.repository_directory}/metadata/<repository_name>/previous

      3.  For each repository, the "current" root metadata file must exist:
            {tuf.conf.repository_directory}/metadata/<repository_name>/current/root.json

    <Arguments>
      updater_name:
        A name to refer to this updater. TODO: Explain why we still need this
        in this new class, if we do. (Don't yet see a reason)

    <Exceptions>
      tuf.FormatError:
        If the arguments are improperly formatted.

      tuf.RepositoryError:
        If there is an error with the updater's repository files, such
        as a missing 'root.json' file.

    <Side Effects>

      pinned.json is read from disk and stored in this new object.
      For each repository, the metadata files (e.g., 'root.json',
      'targets.json') for the top- level roles are read from disk and stored in
      dictionaries.  In addition, the key and roledb modules are populated with
      'repository_name' entries.

    <Returns>
      None.
    """

    # Do the arguments have the correct format?
    # These checks ensure the arguments have the appropriate
    # number of objects and object types and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if there is a mistmatch.
    tuf.formats.NAME_SCHEMA.check_match(updater_name)

    # Save the validated arguments.
    self.updater_name = updater_name

    # Ensure the repository metadata directory has been set.
    if tuf.conf.repository_directory is None:
      raise tuf.RepositoryError('The TUF update client module must specify the'
        ' directory containing the local repository files.'
        '  "tuf.conf.repository_directory" MUST be set.')

    # Set the path for the current set of metadata files.
    client_repositories_directory = tuf.conf.repository_directory

    # Load pinned.json, which is required per TAP #4 and determines which
    # which targets should be sought from which repository(/ies).
    self._load_pinned_metadata(os.path.join(
        client_repositories_directory, 'metadata', 'pinned.json'))

    # This is where the SingleRepoUpdater objects are stored, indexed by
    # repository name.
    self.repositories = {}

    # Create a SingleRepoUpdater object for each repository using pinned.json's
    # repository entry, including the mirrors info.
    for repo_name in self.pinned_metadata['repositories']:
      this_repo = self.pinned_metadata['repositories'][repo_name]
      self.repositories[repo_name] = SingleRepoUpdater(
          repo_name, this_repo['mirrors'])





  def _load_pinned_metadata(self, pinned_metadata_fname):
    """
    Load pinned.json and add default values for unspecified properties
    (currently just 'terminating')
    """
    if not os.path.exists(pinned_metadata_fname):
      raise tuf.RepositoryError('Cannot find pinned.json at ' +
          pinned_metadata_fname + '. This file is required for the '
          'updater per TAP 4 (github.com/theupdateframework/taps).')

    DEFAULT_VALUE_OF_TERMINATING_FLAG = False # TODO: see below, find better place for this

    # Read in pinned.json.
    pinned_metadata = tuf.util.load_json_file(pinned_metadata_fname)

    # Make sure the pinned file matches format expectations.
    tuf.formats.PINNING_FILE_SCHEMA.check_match(pinned_metadata)

    # Rebuild delegations dict to include 'terminating' default.
    # TODO: Consult w/ Vlad about the proper way to handle default values in
    # metadata. "backtrack" was previously treated as if it could be assumed
    # to exist here. I'm not sure how that was filled in when it was missing,
    # but the same mechanism should be employed for "terminating" in pinnings.
    # Meanwhile, here's a hack.
    pinned_metadata_w_defaults_added = {
        'repositories': pinned_metadata['repositories'],
        'delegations': []}
    for this_delegation in pinned_metadata['delegations']:
      if 'terminating' not in this_delegation:
        this_delegation['terminating'] = DEFAULT_VALUE_OF_TERMINATING_FLAG
      pinned_metadata_w_defaults_added['delegations'].append(this_delegation)

    self.pinned_metadata = pinned_metadata_w_defaults_added





  def __str__(self):
    """
      The string representation of an Updater object.
    """

    return self.updater_name



  def refresh(self, unsafely_update_root_if_necessary=True, repo_name=None):
    """
    Runs refresh() on the SingleRepoUpdater corresponding to the given
    repository name. If not provided a repository name, runs refresh() on every
    SingleRepoUpdater (the updaters for every known repository).

    TODO: Docstring this without reproducing the entire string from below. /:
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      self.repositories[repo_name].refresh()

    else:
      for repo_name in self.repositories:
        self.repositories[repo_name].refresh(unsafely_update_root_if_necessary=
          unsafely_update_root_if_necessary)



  def all_targets(self, repo_name=None):
    """
    Returns the output of all_targets() on the updater for the given repository
    name. If not provided a repository name, returns the combined output of
    all_targets() run on the updaters for all known repositories.

    Across repositories, targets are not provided in any particular order.
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].all_targets()

    else:
      all_repos_targets = []

      for repo_name in self.repositories:
        all_repos_targets.extend(self.repositories[repo_name].all_targets())

      return all_repos_targets



  def targets_of_role(self, rolename='targets', repo_name=None):
    """
    Returns the output of targets_of_role(rolename) run on the updater for
    the given repository.
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].targets_of_role(targets)

    else:
      # This case is only intended to handle a single default repository.
      if len(self.repositories) != 1:
        raise tuf.Error("There are multiple repositories known to this "
          "updater, therefore a specific repo_name must be provided in a "
          "targets_of_role call.")

      # Else, run on the first and only repository in the list of known
      # repositories.  TODO: This is clumsy. Improve.
      return self.repositories[[i for i in self.repositories][0]].targets_of_role(
          rolename)





  def _get_pinnings_for_target(self, target_filepath):
    """
    TODO: Docstring

    This function produces a list of the pinned repositories, in order of
    priority in pinned.json, that are delegated this target file.

    <Returns>
      List of lists of repository names.
      e.g. [ ['repo1'], ['repo2'], ['repo3a', 'repo3b'] ]
      Each entry in the list corresponds to a pinning. If the pinning is a
      single-repository pinning, it will be a one-length list. If, say, two
      repositories are pinned in a multi-repository pinning, the list will be
      of both repositories.
    """
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)

    pinnings_for_target = []
    debug__terminating_pinning_encountered = False

    for this_pinning in self.pinned_metadata['delegations']:
      pinning_is_relevant = False

      for delegated_path in this_pinning['paths']:
        if fnmatch.fnmatch(target_filepath, delegated_path):
          pinning_is_relevant = True
          break

      if pinning_is_relevant:

        if 0 == len(this_pinning['repositories']):
          raise tuf.FormatError('Format of pinned.json is wrong. A pinning '
              'delegation has no repositories listed.')

        pinnings_for_target.append(this_pinning['repositories'])
        if this_pinning.get('terminating', False):
          debug__terminating_pinning_encountered = False
          break

    logger.debug('Found the following repository lists in pinnings relevant to'
        ' target ' + repr(target_filepath) + ': ' + repr(pinnings_for_target) +
        debug__terminating_pinning_encountered * 'The last pinning encountered'
        ' was flagged as terminating, so no further pinnings were inspected.')
    return pinnings_for_target





  def target(self, target_filepath, repo_name=None):
    """
    Returns the output of target(target_filepath) run on the updater for the
    given repository.

    If multiple repositories are known to this updater, a repo_name argument
    must be provided. (If only one repository is listed in this updater, then
    that repository is used.)

    <Exceptions>
      tuf.FormatError if there is a pinning delegation that has no repositories
      listed.
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].target(target_filepath)

    # Else, no repo_name was specified.
    # Employ metadata from pinned.json to determine which repository to use.
    # For each pinning (repository delegation), check its delegated
    # paths/patterns to see if the given target_filepath matches.
    # e.g. if the filepath is targets/subpath/target.tgz, and the delegation
    # lists paths ["targets/subpath/*"], then we will try using that
    # repository.
    # Returned here is a list of lists of repository names.
    relevant_pinnings = self._get_pinnings_for_target(target_filepath)

    # Try to fetch target info from each of the relevant pinnings retrieved in
    # the previous line until one succeeds.
    target_info = None

    for repo_list in relevant_pinnings:
      # repo_list corresponds to a single pinning. It will be of length
      # one if we're dealing with a single-repository pinning, and longer if
      # we're dealing with a multi-repository pinning.
      # Code below handles both cases together.

      assert 0 != len(repo_list), 'Programming error. ' + \
          '(Should be impossible due to _get_pinnings_for_target() checks'

      tentative_target = None

      for repo_name in repo_list:
        logger.debug('Checking for target ' + repr(target_filepath) + ' in '
            'repository (' + repr(repo_name) + '), listed in a relevant '
            'pinning.')

        new_tentative_target = None

        try: # Try to get the target from this repository.
          new_tentative_target = self.repositories[repo_name].target(
              target_filepath)

        except tuf.UnknownTargetError as e:
          logger.debug('Checking for target ' + repr(target_filepath) + ' in'
              ' repository (' + repr(repo_name) + ') yielded no target. '
              ' Exception from attempt was: ' + repr(e))

        if new_tentative_target is None:
          # If any of the required repos don't yield target info, then this
          # multi-repository pinning delegation cannot validate the file.
          tentative_target = None
          break

        elif tentative_target is None:
          # If we got target info, and we didn't already have target info from
          # a previous repository, then this was the first repository in this
          # pinning, and we save the target info.
          tentative_target = new_tentative_target

        elif not _target_info_is_equal(
            tentative_target['fileinfo'], new_tentative_target['fileinfo']):

          # If we already have target info from a previous repository and it's
          # not equal to the target info we just fetched, then this multi-repo
          # delegation cannot validate the file.
          # We proceed as if this multi-repo delegation had not specified the
          # target info (allowing the backtrack setting to determine whether
          # or not to continue checking any further delegations).
          logger.debug('A multi-repository pinning delegation had multiple '
              'different specified file infos for the same target. Because '
              'all repositories must agree on file info for a target in a '
              'multi-repository delegation, we proceed as if the delegation '
              'has not provided target info for this file. Skipping this'
                'multi-repository pinning delegation.')
          tentative_target = None
          break # moves to the next pinning

        # Else, new tentative target and tentative target both are non-None
        # and are identical, so we proceed happily to the next repository in
        # the (potentially multi-repository) pinning delegation.

      # We've now checked every repository in this particular pinning.
      # Check result of looking for target info in the delegated-to roles.
      if tentative_target is not None:
        return tentative_target

      else:
        logger.debug('Failed to find target ' + repr(target_filepath) + ' in '
            'this pinning (repos: ' + repr(repo_list) + '). Moving on to next'
            ' pinning.')

    # We should only get here in the code if we have tried every pinning and
    # have not successfully derived target info.
    assert target_info is None, 'Programming error.'

    raise tuf.UnknownTargetError(target_filepath + ' not found.')






  def remove_obsolete_targets(self, destination_directory, repo_name=None):
    """
    Run remove_obsolete_targets(destination_directory) on the updater for the
    given repository.

    If multiple repositories are known to this updater, a repo_name argument
    must be provided. (If only one repository is listed in this updater, then
    that repository is used.)
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].remove_obsolete_targets(
          destination_directory)

    else:
      # This case is only intended to handle a single default repository.
      if len(self.repositories) != 1:
        raise tuf.Error("There are multiple repositories known to this "
          "updater, therefore a specific repo_name must be provided in an "
          "remove_obsolete_targets call.")

      # Else, run on the first and only repository in the list of known
      # repositories.  TODO: This is clumsy. Improve.
      self.repositories[[i for i in self.repositories][0]].remove_obsolete_targets(
          destination_directory)





  def updated_targets(self, targets, destination_directory, repo_name=None):
    """
    Returns the output of updated_targets(targets, destination_directory) on
    the updater for the given repository name.

    If multiple repositories are known to this updater, a repo_name argument
    must be provided. (If only one repository is listed in this updater, then
    that repository is used.)
    """
    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].updated_targets(targets,
          destination_directory)

    else:
      # This case is only intended to handle a single default repository.
      if len(self.repositories) != 1:
        raise tuf.Error("There are multiple repositories known to this "
          "updater, therefore a specific repo_name must be provided in an "
          "updated_targets call.")

      # Run on the first and only repository in the list of known repositories.
      # TODO: Clumsy.
      return self.repositories[[i for i in self.repositories][0]].updated_targets(
          targets, destination_directory)





  def download_target(self, target, destination_directory, repo_name=None):
    """
    Returns the output of download_target(target, destination_directory) on
    the updater for the given repository name.

    If multiple repositories are known to this updater, a repo_name argument
    must be provided. (If only one repository is listed in this updater, then
    that repository is used.)


    TODO: DESIGN CHECK! This function is a little weird in that it is willing
    to download the target from any repository in any relevant pinning, even if
    the target info came from a different repository. That target info will
    still be used to validate this download, regardless of where the file ended
    up coming from.

    """

    # Check arguments.
    tuf.formats.TARGETFILE_SCHEMA.check_match(target)
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    if repo_name is not None:
      self._validate_repo_name(repo_name)
      return self.repositories[repo_name].download_target(target,
          destination_directory)

    # If we have not been specifically instructed by the client to use a
    # particular repository, then we process pinned.json metadata in order to
    # determine which repository to use.

    relevant_pinnings = self._get_pinnings_for_target(target['filepath'])

    # For each delegation (repo_list) below, save a list of tuf.NoWorkingMirror
    # exceptions generated, to return as part of the raised exception if all
    # attempts at acquiring the target fail. This includes exceptions from each
    # repository listed in each delegation.
    #
    # In the following example, we see a NoWorkingMirrorError from the only
    # repo listed in the first delegation, and then from the two repos listed
    # in a multi-repository second delegation.
    #
    #   exceptions_from_all_delegations = [
    #       tuf.NoWorkingMirrorError(
    #           <the individual exceptions from each mirror for Repo1>),
    #       tuf.NoWorkingMirrorError(...),
    #       tuf.NoWorkingMirrorError(...)
    #    ]
    exceptions_from_all_delegations = []

    # Try every delegation from pinned.json that is relevant to the target,
    # in order.
    for repo_list in relevant_pinnings:
      # repo_list corresponds to a single pinning. It will be of length
      # one if we're dealing with a single-repository pinning, and longer if
      # we're dealing with a multi-repository pinning.
      # Code below handles both cases together.

      assert 0 != len(repo_list), 'Programming error. ' + \
          '(Should be impossible due to _get_pinnings_for_target() checks'

      for repo_name in repo_list:
        # This pinning may be a single-repo or multi-repo pinning. For each
        # repository in this pinning, try downloading the target file.

        list_of_noworkingmirror_exceptions = []

        try:
          self.repositories[repo_name].download_target(
              target, destination_directory)

        except tuf.NoWorkingMirrorError as e:
          exceptions_from_all_delegations.append(e)

        else:
          logger.debug('Succeeded in downloading target ' +
              repr(target['filepath']) + ' from repo ' + repr(repo_name))
          return

    # We land here if all attempts for all repositories listed in all relevant
    # delegations have failed to yield a valid target.
    # Spool the errors from all mirrors of all repositories in all delegations.
    all_mirror_errors = {}
    for nwme in exceptions_from_all_delegations:
      for mirror_url, mirror_error in six.iteritems(e.mirror_errors):
        # TODO: <~> THE FOLLOWING LINE IS FLAWED!
        # If there are mirrors of the same URL in multiple repositories
        # (which will occur for a common use case!), then there will be
        # collisions in the key space for this dictionary.
        # As it is, previous attempts to hit the same URL are overwritten.
        # It's probably not wise to increase the depth of the structure of
        # NoWorkingMirrorErrors, so that option is probably out.
        # We can add some prefix relating to the delegation to prevent
        # this. (Delegations don't have names, though.)
        all_mirror_errors[mirror_url] = mirror_error

    raise tuf.NoWorkingMirrorError(all_mirror_errors)





  def _validate_repo_name(self, repo_name):
    """
    Throws tuf.FormatError if the given repo_name is not of the right type.
    Throws tuf.Error if the given repo_name is not that of a known repository.
    """
    tuf.formats.REPOSITORY_NAME_SCHEMA.check_match(repo_name)

    if repo_name not in self.repositories:
      raise tuf.Error('Unknown repository specified in attempt to load '
          'metadata from file. Repo name: ' + repr(repo_name) + '; only aware '
          'of these repositories: ' +
          repr([r for r in self.repositories]))





  def get_metadata(self, repo_name, metadata_set):
    """
    TODO: Docstring

    repo_name is from self.repositories
    metadata_set is either 'current' or 'previous'
    """
    self._validate_repo_name(repo_name)
    _validate_metadata_set(metadata_set)

    return self.repositories[repo_name].metadata[metadata_set]





class SingleRepoUpdater(object):
  """
  <Purpose>
    Provide a class that can download target files securely.  The updater
    keeps track of currently and previously trusted metadata, target files
    available to the client, target file attributes such as file size and 
    hashes, key and role information, metadata signatures, and the ability
    to determine when the download of a file should be permitted.

  <Updater Attributes>
    self.metadata:
      Dictionary holding the currently and previously trusted metadata.
      
      Example: {'current': {'root': ROOT_SCHEMA,
                            'targets':TARGETS_SCHEMA, ...},
                'previous': {'root': ROOT_SCHEMA,
                             'targets':TARGETS_SCHEMA, ...}}
    
    self.metadata_directory:
      The directory where trusted metadata is stored.
      
    self.versioninfo:
      A cache of version numbers for the roles available on the repository.
      
      Example: {'targets.json': {'version': 128}, ...}

    self.mirrors:
      The repository mirrors from which metadata and targets are available.
      Conformant to 'tuf.formats.ALT_MIRRORLIST_SCHEMA'.
    
    self.repository_name:
      This is the name of the repository that this updater object will use.
      It is expected to be the name of the repository as you would see it in
      pinned.json, and in the roledb and keydb dictionaries.

    self.root_override_URLs:
      This is an optional argument that allows us to specify the url from which
      to retrieve root.json in particular. This is of use for key-pinning
      configurations in which there is a custom (local, or separately remotely
      hosted) root file, but the rest of the metadata is still available at
      the expected location for the repository.




  <Updater Methods>
    refresh():
      This method downloads, verifies, and loads metadata for the top-level
      roles in a specific order (i.e., timestamp -> snapshot -> root -> targets)
      The expiration time for downloaded metadata is also verified.
      
      The metadata for delegated roles are not refreshed by this method, but by
      the target methods (e.g., all_targets(), targets_of_role(), target()).
      The refresh() method should be called by the client before any target
      requests.
    
    all_targets():
      Returns the target information for the 'targets' and delegated roles.
      Prior to extracting the target information, this method attempts a file
      download of all the target metadata that have changed.
    
    targets_of_role('targets'):
      Returns the target information for the targets of a specified role.
      Like all_targets(), delegated metadata is updated if it has changed.
    
    target(file_path):
      Returns the target information for a specific file identified by its file
      path.  This target method also downloads the metadata of updated targets.
    
    updated_targets(targets, destination_directory):
      After the client has retrieved the target information for those targets
      they are interested in updating, they would call this method to determine
      which targets have changed from those saved locally on disk.  All the
      targets that have changed are returns in a list.  From this list, they
      can request a download by calling 'download_target()'.
    
    download_target(target, destination_directory):
      This method performs the actual download of the specified target.  The
      file is saved to the 'destination_directory' argument.

    remove_obsolete_targets(destination_directory):
      Any files located in 'destination_directory' that were previously
      served by the repository but have since been removed, can be deleted
      from disk by the client by calling this method.

    Note: The methods listed above are public and intended for the software
    updater integrating TUF with this module.  All other methods that may begin
    with a single leading underscore are non-public and only used internally.
    updater.py is not subclassed in TUF, nor is it designed to be subclassed,
    so double leading underscores is not used.
    http://www.python.org/dev/peps/pep-0008/#method-names-and-instance-variables
  """

  def __init__(self, repository_name, repository_mirrors):
    """
    <Purpose>
      Constructor.  Instantiating an updater object causes all the metadata
      files for the top-level roles to be read from disk, including the key
      and role information for the delegated targets of 'targets'.  The actual
      metadata for delegated roles is not loaded in __init__.  The metadata
      for these delegated roles, including nested delegated roles, are
      loaded, updated, and saved to the 'self.metadata' store by the target
      methods, like all_targets() and targets_of_role().
      
      The initial set of metadata files are provided by the software update
      system utilizing TUF.
      
      In order to use an updater, the following directories must already
      exist locally:
            
        {tuf.conf.repository_directory}/metadata/<repository_name>/current
        {tuf.conf.repository_directory}/metadata/<repository_name>previous
      
      and, at a minimum, the root metadata file must exist:

        {tuf.conf.repository_directory}/metadata/<repository_name>/current/root.json
    
    <Arguments>
      repository_name:
        This is the name of the repository that this updater object will use.
        It is expected to be the name of the repository as you would see it in
        pinned.json, and in the roledb and keydb dictionaries.

      repository_mirrors:
        A list of URLs (each of type tuf.formats.URL_SCHEMA, which is
        at the time of this writing a simple string).

        Old:
          # repository_mirrors:
          #   A dictionary holding repository mirror information, conformant to
          #   'tuf.formats.MIRRORDICT_SCHEMA'.  This dictionary holds information
          #   such as the directory containing the metadata and target files, the
          #   server's URL prefix, and the target content directories the client
          #   should be confined to.

          #   repository_mirrors = {'mirror1': {'url_prefix': 'http://localhost:8001',
          #                                     'metadata_path': 'metadata',
          #                                     'targets_path': 'targets',
          #                                     'confined_target_dirs': ['']}}
    
    <Exceptions>
      tuf.FormatError:
        If the arguments are improperly formatted. 
      
      tuf.RepositoryError:
        If there is an error with the updater's repository files, such
        as a missing 'root.json' file.

    <Side Effects>
      The metadata files (e.g., 'root.json', 'targets.json') for the top- level
      roles are read from disk and stored in dictionaries.  In addition, the
      key and roledb modules are populated with 'repository_name' entries.

    <Returns>
      None.
    """
  
    # Do the arguments have the correct format?
    # These checks ensure the arguments have the appropriate
    # number of objects and object types and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if there is a mistmatch.
    tuf.formats.NAME_SCHEMA.check_match(repository_name)
    tuf.formats.ALT_MIRRORLIST_SCHEMA.check_match(repository_mirrors)
   
    # Save the validated arguments.
    self.repository_name = repository_name
    self.mirrors = repository_mirrors

    # Store the trusted metadata read from disk.
    self.metadata = {}
    
    # Store the currently trusted/verified metadata.
    self.metadata['current'] = {} 
    
    # Store the previously trusted/verified metadata.
    self.metadata['previous'] = {}

    # Store the version numbers of roles available on the repository.  The dict
    # keys are paths, and the dict values versioninfo data. This information
    # can help determine whether a metadata file has changed and needs to be
    # re-downloaded.
    self.versioninfo = {}

    # Store the file information of the root and snapshot roles.  The dict keys
    # are paths, the dict values fileinfo data. This information can help
    # determine whether a metadata file has changed and so needs to be
    # re-downloaded.
    self.fileinfo = {}
    
    # Prepare to store the location of the client's metadata directories,
    # current and previous.
    self.metadata_directory = {}

    # Store the 'consistent_snapshot' of the Root role.  This setting
    # determines if metadata and target files downloaded from remote
    # repositories include the digest.
    self.consistent_snapshot = False
    
    # Ensure the repository metadata directory has been set.
    if tuf.conf.repository_directory is None:
      raise tuf.RepositoryError("The TUF update client module must specify the"
        " directory containing the client's local repository files."
        "  'tuf.conf.repository_directory' MUST be set.")

    # Set the path for the current set of metadata files.  
    client_repositories_directory = tuf.conf.repository_directory
    current_path = os.path.join(client_repositories_directory, 'metadata',
        repository_name, 'current')
    
    # Ensure the current path is valid/exists before saving it.
    if not os.path.exists(current_path):
      raise tuf.RepositoryError('Missing ' + repr(current_path) + '.'
        '  This path must exist and, at a minimum, contain the Root'
        ' metadata file.')

    self.metadata_directory['current'] = current_path
    
    # Set the path for the previous set of metadata files. 
    previous_path = os.path.join(client_repositories_directory, 'metadata',
        repository_name, 'previous')
   
    # Ensure the previous path is valid/exists.
    if not os.path.exists(previous_path):
      raise tuf.RepositoryError('Missing ' + repr(previous_path) + '.'
        '  This path MUST exist.')

    self.metadata_directory['previous'] = previous_path
    
    # Load current and previous metadata.
    for metadata_set in ['current', 'previous']:
      for metadata_role in ['root', 'targets', 'snapshot', 'timestamp']:
        self._load_metadata_from_file(metadata_set, metadata_role)
      
    # Raise an exception if the repository is missing the required 'root'
    # metadata.
    if 'root' not in self.metadata['current']:
      raise tuf.RepositoryError('No root of trust! Could not find the'
        ' "root.json" file.')





  def __str__(self):
    """
      The string representation of an Updater object.
    """
    
    return self.repository_name





  def _load_metadata_from_file(self, metadata_set, metadata_role):
    """
    <Purpose>
      Non-public method that loads current or previous metadata if there is a
      local file.  If the expected file belonging to 'metadata_role' (e.g.,
      'root.json') cannot be loaded, raise an exception.  The extracted metadata
      object loaded from file is saved to the metadata store (i.e.,
      self.metadata).
        
    <Arguments>        
      metadata_set:
        The string 'current' or 'previous', depending on whether one wants to
        load the currently or previously trusted metadata file.
            
      metadata_role:
        The name of the metadata. This is a role name and should
        not end in '.json'.  Examples: 'root', 'targets', 'unclaimed'.

    <Exceptions>
      tuf.FormatError:
        If the role object loaded for 'metadata_role' is improperly formatted.

      tuf.Error:
        If there was an error importing a delegated role of 'metadata_role'
        or the 'metadata_set' is not one currently supported.
    
    <Side Effects>
      If the metadata is loaded successfully, it is saved to the metadata
      store.  If 'metadata_role' is 'root', the role and key databases
      are reloaded.  If 'metadata_role' is a target metadata, all its
      delegated roles are refreshed.

    <Returns>
      None.
    """

    # Ensure we have a valid metadata set.
    _validate_metadata_set(metadata_set)

    # Save and construct the full metadata path.
    metadata_directory = self.metadata_directory[metadata_set]
    metadata_filename = metadata_role + '.json'
    metadata_filepath = os.path.join(metadata_directory, metadata_filename)
    
    # Ensure the metadata path is valid/exists, else ignore the call. 
    if os.path.exists(metadata_filepath):
      # Load the file.  The loaded object should conform to
      # 'tuf.formats.SIGNABLE_SCHEMA'.
      metadata_signable = tuf.util.load_json_file(metadata_filepath)

      tuf.formats.check_signable_object_format(metadata_signable)

      # Extract the 'signed' role object from 'metadata_signable'.
      metadata_object = metadata_signable['signed']
   
      # Save the metadata object to the metadata store.
      self.metadata[metadata_set][metadata_role] = metadata_object
  
      # If 'metadata_role' is 'root' or targets metadata, the key and role
      # databases must be rebuilt.  If 'root', ensure self.consistent_snaptshots
      # is updated.
      if metadata_set == 'current':
        if metadata_role == 'root':
          self._rebuild_key_and_role_db()
          self.consistent_snapshot = metadata_object['consistent_snapshot']
        
        elif metadata_object['_type'] == 'Targets':
          # TODO: Should we also remove the keys of the delegated roles?
          self._import_delegations(metadata_role)





  def _rebuild_key_and_role_db(self):
    """
    <Purpose>
      Non-public method that rebuilds the key and role databases from the
      currently trusted 'root' metadata object extracted from 'root.json'.
      This private method is called when a new/updated 'root' metadata file is
      loaded.  This method will only store the role information of the
      top-level roles (i.e., 'root', 'targets', 'snapshot', 'timestamp').

    <Arguments>
      None.

    <Exceptions>
      tuf.FormatError:
        If the 'root' metadata is improperly formatted.

      tuf.Error:
        If there is an error loading a role contained in the 'root'
        metadata.

    <Side Effects>
      The key and role databases are reloaded for the top-level roles.

    <Returns>
      None.
    """
    
    # Clobbering this means all delegated metadata files are rendered outdated
    # and will need to be reloaded.  However, reloading the delegated metadata
    # files is avoided here because fetching target information with methods
    # like all_targets() and target() always cause a refresh of these files.
    # The metadata files for delegated roles are also not loaded when the
    # repository is first instantiated.  Due to this setup, reloading delegated
    # roles is not required here.
    tuf.keydb.create_keydb_from_root_metadata(self.metadata['current']['root'],
                                              self.repository_name)
    tuf.roledb.create_roledb_from_root_metadata(self.metadata['current']['root'],
                                                self.repository_name)





  def _import_delegations(self, parent_role):
    """
    <Purpose>
      Non-public method that imports all the roles delegated by 'parent_role'.
    
    <Arguments>
      parent_role:
        The role whose delegations will be imported.
        
    <Exceptions>
      tuf.FormatError:
        If a key attribute of a delegated role's signing key is
        improperly formatted.

      tuf.Error:
        If the signing key of a delegated role cannot not be loaded.

    <Side Effects>
      The key and role databases are modified to include the newly loaded roles
      delegated by 'parent_role'.

    <Returns>
      None.
    """
        
    current_parent_metadata = self.metadata['current'][parent_role]
  
    if 'delegations' not in current_parent_metadata:
      return

    # This could be quite slow with a large number of delegations.
    keys_info = current_parent_metadata['delegations'].get('keys', {})
    roles_info = current_parent_metadata['delegations'].get('roles', [])

    logger.debug('Adding roles delegated from ' + repr(parent_role) + '.')
   
    # Iterate the keys of the delegated roles of 'parent_role' and load them.
    for keyid, keyinfo in six.iteritems(keys_info):
      if keyinfo['keytype'] in ['rsa', 'ed25519']:
        key, keyids = tuf.keys.format_metadata_to_key(keyinfo)
      
        # We specify the keyid to ensure that it's the correct keyid
        # for the key.
        try:
          tuf.keydb.add_key(key, keyid, self.repository_name)
          for keyid in keyids:
            key['keyid'] = keyid
            tuf.keydb.add_key(key, keyid=None, repository_name=self.repository_name)

        except tuf.KeyAlreadyExistsError:
          pass
        
        except (tuf.FormatError, tuf.Error):
          logger.exception('Invalid key for keyid: ' + repr(keyid) + '.')
          logger.error('Aborting role delegation for parent role ' + parent_role + '.')
          raise
      
      else:
        logger.warning('Invalid key type for ' + repr(keyid) + '.')
        continue

    # Add the roles to the role database.
    for roleinfo in roles_info:
      try:
        # NOTE: tuf.roledb.add_role will take care of the case where rolename
        # is None.
        rolename = roleinfo.get('name')
        logger.debug('Adding delegated role: ' + str(rolename) + '.')
        tuf.roledb.add_role(rolename, roleinfo, self.repository_name)
      
      except tuf.RoleAlreadyExistsError:
        logger.warning('Role already exists: ' + rolename)
      
      except:
        logger.exception('Failed to add delegated role: ' + rolename + '.')
        raise





  def refresh(self, unsafely_update_root_if_necessary=True):
    """
    <Purpose>
      Update the latest copies of the metadata for the top-level roles. The
      update request process follows a specific order to ensure the metadata
      files are securely updated:
      timestamp -> snapshot -> root (if necessary) -> targets.
      
      Delegated metadata is not refreshed by this method. After this method is
      called, the use of target methods (e.g., all_targets(),
      targets_of_role(), or target()) will update delegated metadata, when
      required.  Calling refresh() ensures that top-level metadata is
      up-to-date, so that the target methods can refer to the latest available
      content. Thus, refresh() should always be called by the client before any
      requests of target file information.

      The expiration time for downloaded metadata is also verified, including
      local metadata that the repository claims is up to date.

      If the refresh fails for any reason, then unless
      'unsafely_update_root_if_necessary' is set, refresh will be retried once
      after first attempting to update the root metadata file. Only after this
      check will the exceptions listed here potentially be raised.

    <Arguments>
      unsafely_update_root_if_necessary:
        Boolean that indicates whether to unsafely update the Root metadata if
        any of the top-level metadata cannot be downloaded successfully.  The
        Root role is unsafely updated if its current version number is unknown.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        If the metadata for any of the top-level roles cannot be updated.

      tuf.ExpiredMetadataError:
         If any of the top-level metadata is expired (whether a new version was
         downloaded expired or no new version was found and the existing
         version is now expired). 
        
    <Side Effects>
      Updates the metadata files of the top-level roles with the latest
      information.

    <Returns>
      None.
    """
    
    # Do the arguments have the correct format? 
    # This check ensures the arguments have the appropriate 
    # number of objects and object types, and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if the check fail.
    tuf.formats.BOOLEAN_SCHEMA.check_match(unsafely_update_root_if_necessary)

    # The Timestamp role does not have signed metadata about it; otherwise we
    # would need an infinite regress of metadata. Therefore, we use some
    # default, but sane, upper file length for its metadata.
    DEFAULT_TIMESTAMP_UPPERLENGTH = tuf.conf.DEFAULT_TIMESTAMP_REQUIRED_LENGTH

    # The Root role may be updated without knowing its version number if
    # top-level metadata cannot be safely downloaded (e.g., keys may have been
    # revoked, thus requiring a new Root file that includes the updated keys)
    # and 'unsafely_update_root_if_necessary' is True.
    # We use some default, but sane, upper file length for its metadata.
    DEFAULT_ROOT_UPPERLENGTH = tuf.conf.DEFAULT_ROOT_REQUIRED_LENGTH

    # Update the top-level metadata.  The _update_metadata_if_changed() and
    # _update_metadata() calls below do NOT perform an update if there
    # is insufficient trusted signatures for the specified metadata.
    # Raise 'tuf.NoWorkingMirrorError' if an update fails.

    # Is the Root role expired?  When the top-level roles are initially loaded
    # from disk, their expiration is not checked to allow their updating when
    # requested (and give the updater the chance to continue, rather than always
    # failing with an expired metadata error.)  If
    # 'unsafely_update_root_if_necessary' is True, update an expired Root role
    # now.  Updating the other top-level roles, regardless of their validity,
    # should only occur if the root of trust is up-to-date.
    root_metadata = self.metadata['current']['root']
    try: 
      self._ensure_not_expired(root_metadata, 'root')
    
    except tuf.ExpiredMetadataError:
      # Raise 'tuf.NoWorkingMirrorError' if a valid (not expired, properly
      # signed, and valid metadata) 'root.json' cannot be installed.
      if unsafely_update_root_if_necessary:
        message = \
          'Expired Root metadata was loaded from disk.  Try to update it now.' 
        logger.info(message)
        self._update_metadata('root', DEFAULT_ROOT_UPPERLENGTH)
     
      # The caller explicitly requested not to unsafely fetch an expired Root.
      else:
        logger.info('An expired Root metadata was loaded and must be updated.')
        raise

    # If an exception is raised during the metadata update attempts, we will
    # attempt to update root metadata once by recursing with a special argument
    # (unsafely_update_root_if_necessary) to avoid further recursion.

    # Use default but sane information for timestamp metadata, and do not
    # require strict checks on its required length.
    try: 
      self._update_metadata('timestamp', DEFAULT_TIMESTAMP_UPPERLENGTH)
      self._update_metadata_if_changed('snapshot',
                                       referenced_metadata='timestamp')
      self._update_metadata_if_changed('root')
      self._update_metadata_if_changed('targets')
    
    # There are two distinct error scenarios that can rise from the
    # _update_metadata_if_changed calls in the try block above:
    #
    #   - tuf.NoWorkingMirrorError:
    #
    #      If a change to a metadata file IS detected in an
    #      _update_metadata_if_changed call, but we are unable to download a
    #      valid (not expired, properly signed, valid) version of that metadata
    #      file, a tuf.NoWorkingMirrorError rises to this point.
    # 
    #   - tuf.ExpiredMetadataError:
    #
    #      If, on the other hand, a change to a metadata file IS NOT detected
    #      in a given _update_metadata_if_changed call, but we observe that the
    #      version of the metadata file we have on hand is now expired, a
    #      tuf.ExpiredMetadataError exception rises to this point.
    #
    except tuf.NoWorkingMirrorError:
      if unsafely_update_root_if_necessary:
        logger.info('Valid top-level metadata cannot be downloaded.  Unsafely'
          ' update the Root metadata.')
        self._update_metadata('root', DEFAULT_ROOT_UPPERLENGTH)
        self.refresh(unsafely_update_root_if_necessary=False)

      else:
        raise

    except tuf.ExpiredMetadataError:
      if unsafely_update_root_if_necessary:
        logger.info('No changes were detected from the mirrors for a given role'
          ', and that metadata that is available on disk has been found to be'
          ' expired. Trying to update root in case of foul play.')
        self._update_metadata('root', DEFAULT_ROOT_UPPERLENGTH)
        self.refresh(unsafely_update_root_if_necessary=False)

      # The caller explicitly requested not to unsafely fetch an expired Root.
      else:
        logger.info('No changes were detected from the mirrors for a given role'
          ', and that metadata that is available on disk has been found to be '
          'expired. Your metadata is out of date.')
        raise





  def _check_hashes(self, file_object, trusted_hashes):
    """
    <Purpose>
      Non-public method that verifies multiple secure hashes of the downloaded
      file 'file_object'.  If any of these fail it raises an exception.  This is
      to conform with the TUF spec, which support clients with different hashing
      algorithms. The 'hash.py' module is used to compute the hashes of
      'file_object'.

    <Arguments>
      file_object:
        A 'tuf.util.TempFile' file-like object.  'file_object' ensures that a
        read() without a size argument properly reads the entire file.

      trusted_hashes:
        A dictionary with hash-algorithm names as keys and hashes as dict values.
        The hashes should be in the hexdigest format.  Should be Conformant to
        'tuf.formats.HASHDICT_SCHEMA'.

    <Exceptions>
      tuf.BadHashError, if the hashes don't match.

    <Side Effects>
      Hash digest object is created using the 'tuf.hash' module.

    <Returns>
      None.
    """

    # Verify each trusted hash of 'trusted_hashes'.  If all are valid, simply
    # return.
    for algorithm, trusted_hash in six.iteritems(trusted_hashes):
      digest_object = tuf.hash.digest(algorithm)
      digest_object.update(file_object.read())
      computed_hash = digest_object.hexdigest()
      
      # Raise an exception if any of the hashes are incorrect.
      if trusted_hash != computed_hash:
        raise tuf.BadHashError(trusted_hash, computed_hash)
      else:
        logger.info('The file\'s '+algorithm+' hash is correct: '+trusted_hash)





  def _hard_check_file_length(self, file_object, trusted_file_length):
    """
    <Purpose>
      Non-public method that ensures the length of 'file_object' is strictly
      equal to 'trusted_file_length'.  This is a deliberately redundant
      implementation designed to complement
      tuf.download._check_downloaded_length().

    <Arguments>
      file_object:
        A 'tuf.util.TempFile' file-like object.  'file_object' ensures that a
        read() without a size argument properly reads the entire file.

      trusted_file_length:
        A non-negative integer that is the trusted length of the file.

    <Exceptions>
      tuf.DownloadLengthMismatchError, if the lengths do not match.

    <Side Effects>
      Reads the contents of 'file_object' and logs a message if 'file_object'
      matches the trusted length.

    <Returns>
      None.
    """

    # Read the entire contents of 'file_object', a 'tuf.util.TempFile' file-like
    # object that ensures the entire file is read.
    observed_length = len(file_object.read())
   
    # Return and log a message if the length 'file_object' is equal to
    # 'trusted_file_length', otherwise raise an exception.  A hard check
    # ensures that a downloaded file strictly matches a known, or trusted,
    # file length.
    if observed_length != trusted_file_length:
      raise tuf.DownloadLengthMismatchError(trusted_file_length,
                                            observed_length)
    else:
      logger.debug('Observed length ('+str(observed_length)+\
                   ') == trusted length ('+str(trusted_file_length)+')')





  def _soft_check_file_length(self, file_object, trusted_file_length):
    """
    <Purpose>
      Non-public method that checks the trusted file length of a
      'tuf.util.TempFile' file-like object. The length of the file must be less
      than or equal to the expected length. This is a deliberately redundant
      implementation designed to complement
      tuf.download._check_downloaded_length().

    <Arguments>
      file_object:
        A 'tuf.util.TempFile' file-like object.  'file_object' ensures that a
        read() without a size argument properly reads the entire file.

      trusted_file_length:
        A non-negative integer that is the trusted length of the file.

    <Exceptions>
      tuf.DownloadLengthMismatchError, if the lengths do not match.

    <Side Effects>
      Reads the contents of 'file_object' and logs a message if 'file_object'
      is less than or equal to the trusted length.

    <Returns>
      None.
    """

    # Read the entire contents of 'file_object', a 'tuf.util.TempFile' file-like
    # object that ensures the entire file is read.
    observed_length = len(file_object.read()) 
   
    # Return and log a message if 'file_object' is less than or equal to
    # 'trusted_file_length', otherwise raise an exception.  A soft check
    # ensures that an upper bound restricts how large a file is downloaded.
    if observed_length > trusted_file_length:
      raise tuf.DownloadLengthMismatchError(trusted_file_length,
                                            observed_length)
    else:
      logger.debug('Observed length ('+str(observed_length)+\
                   ') <= trusted length ('+str(trusted_file_length)+')')





  def _get_target_file(self, target_filepath, file_length, file_hashes):
    """
    <Purpose>
      Non-public method that safely (i.e., the file length and hash are strictly
      equal to the trusted) downloads a target file up to a certain length, and
      checks its hashes thereafter.

    <Arguments>
      target_filepath:
        The target filepath (relative to the repository targets directory)
        obtained from TUF targets metadata.

      file_length:
        The expected compressed length of the target file. If the file is not
        compressed, then it will simply be its uncompressed length.

      file_hashes:
        The expected hashes of the target file.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The target could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired target file.

    <Side Effects>
      The target file is downloaded from all known repository mirrors in the
      worst case. If a valid copy of the target file is found, it is stored in
      a temporary file and returned.

    <Returns>
      A 'tuf.util.TempFile' file-like object containing the target.
    """

    # Define a callable function that is passed as an argument to _get_file()
    # and called.  The 'verify_target_file' function ensures the file length
    # and hashes of 'target_filepath' are strictly equal to the trusted values.
    def verify_target_file(target_file_object):
      
      # Every target file must have its length and hashes inspected.
      self._hard_check_file_length(target_file_object, file_length)
      self._check_hashes(target_file_object, file_hashes)

    # Target files, unlike metadata files, are not decompressed; the
    # 'compression' argument to _get_file() is needed only for decompression of
    # metadata.  Target files may be compressed or uncompressed.
    if self.consistent_snapshot:
      target_digest = random.choice(list(file_hashes.values()))
      dirname, basename = os.path.split(target_filepath)
      target_filepath = os.path.join(dirname, target_digest + '.' + basename)

    return self._get_file(target_filepath, verify_target_file,
                          'target', file_length, compression=None,
                          verify_compressed_file_function=None,
                          download_safely=True)





  def _verify_uncompressed_metadata_file(self, metadata_file_object,
                                         metadata_role):
    """
    <Purpose>
      Non-public method that verifies an uncompressed metadata file.  An
      exception is raised if 'metadata_file_object is invalid.  There is no
      return value.

    <Arguments>
      metadata_file_object:
        A 'tuf.util.TempFile' instance containing the metadata file.
        'metadata_file_object' ensures the entire file is returned with read().

      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets',
        'unclaimed').

    <Exceptions>
      tuf.FormatError:
        In case the metadata file is valid JSON, but not valid TUF metadata.

      tuf.InvalidMetadataJSONError:
        In case the metadata file is not valid JSON.

      tuf.ReplayedMetadataError:
        In case the downloaded metadata file is older than the current one.

      tuf.RepositoryError:
        In case the repository is somehow inconsistent; e.g. a parent has not
        delegated to a child (contrary to expectations).

      tuf.SignatureError:
        In case the metadata file does not have a valid signature.

    <Side Effects>
      The content of 'metadata_file_object' is read and loaded.

    <Returns>
      None.
    """

    metadata = metadata_file_object.read().decode('utf-8')
    
    try:
      metadata_signable = tuf.util.load_json_string(metadata)
    
    except Exception as exception:
      raise tuf.InvalidMetadataJSONError(exception)
    
    else:
      # Ensure the loaded 'metadata_signable' is properly formatted.  Raise
      # 'tuf.FormatError' if not.
      tuf.formats.check_signable_object_format(metadata_signable)

    # Is 'metadata_signable' expired?
    self._ensure_not_expired(metadata_signable['signed'], metadata_role)
   
    # We previously verified version numbers in this function, but have since
    # moved version number verification to the functions that retrieve
    # metadata.

    # Verify the signature on the downloaded metadata object.
    valid = tuf.sig.verify(metadata_signable, metadata_role, self.repository_name)
    
    if not valid:
      raise tuf.BadSignatureError(metadata_role)





  def _unsafely_get_metadata_file(self, metadata_role, metadata_filepath,
                                  uncompressed_fileinfo,
                                  compression=None, compressed_fileinfo=None):

    """
    <Purpose>
      Non-public method that downloads a metadata file up to a certain length.
      The actual file length may not be strictly equal to its expected length.
      File hashes will not be checked because it is expected to be unknown.

    <Arguments>
      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets',
        'claimed').

      metadata_filepath:
        The metadata filepath (i.e., relative to the repository metadata
        directory).

      uncompressed_fileinfo:
        The trusted file length and hashes of the uncompressed version of the 
        metadata file.  Should be 'tuf.formats.FILEINFO_SCHEMA'.

      compression:
        The name of the compression algorithm (e.g., 'gzip'), if the metadata
        file is compressed. 
        
      compressed_fileinfo:
        The fileinfo of the metadata file, if it is compressed.  Should be
        'tuf.formats.FILEINFO_SCHEMA'.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The metadata file is downloaded from all known repository mirrors in the
      worst case. If a valid copy of the metadata file is found, it is stored
      in a temporary file and returned.

    <Returns>
      A 'tuf.util.TempFile' file-like object containing the metadata.
    """
   
    # Store file length and hashes of the uncompressed version metadata.
    # The uncompressed version is always verified.
    uncompressed_file_length = uncompressed_fileinfo['length']
    uncompressed_file_hashes = uncompressed_fileinfo['hashes']
    download_file_length = uncompressed_file_length
    compressed_file_length = None
    compressed_file_hashes = None

    # Store the file length and hashes of the compressed version of the
    # metadata, if compressions is set.
    if compression is not None and compressed_fileinfo is not None:
      compressed_file_length = compressed_fileinfo['length']
      compressed_file_hashes = compressed_fileinfo['hashes']
      download_file_length = compressed_file_length

    def unsafely_verify_uncompressed_metadata_file(metadata_file_object):
      self._soft_check_file_length(metadata_file_object,
                                   uncompressed_file_length)
      self._check_hashes(metadata_file_object, uncompressed_file_hashes)
      self._verify_uncompressed_metadata_file(metadata_file_object,
                                              metadata_role)
      
    def unsafely_verify_compressed_metadata_file(metadata_file_object):
      self._hard_check_file_length(metadata_file_object, compressed_file_length) 
      self._check_hashes(metadata_file_object, compressed_file_hashes)

    if compression is None:
      unsafely_verify_compressed_metadata_file = None

    return self._get_file(metadata_filepath,
                          unsafely_verify_uncompressed_metadata_file, 'meta',
                          download_file_length, compression,
                          unsafely_verify_compressed_metadata_file,
                          download_safely=False)





  def _get_metadata_file(self, metadata_role, remote_filename,
                         upperbound_filelength, expected_version,
                         compression_algorithm):
    """
    <Purpose>
      Non-public method that tries downloading, up to a certain length, a
      metadata file from a list of known mirrors. As soon as the first valid
      copy of the file is found, the downloaded file is returned and the
      remaining mirrors are skipped.

    <Arguments>
      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets', 'unclaimed').

      remote_filename:
        The relative file path (on the remove repository) of 'metadata_role'.

      upperbound_filelength:
        The expected length, or upper bound, of the metadata file to be
        downloaded.

      expected_version:
        The expected and required version number of the 'metadata_role' file
        downloaded.  'expected_version' is an integer.

      compression_algorithm:
        The name of the compression algorithm (e.g., 'gzip').  The algorithm is
        needed if the remote metadata file is compressed. 

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The file is downloaded from all known repository mirrors in the worst
      case. If a valid copy of the file is found, it is stored in a temporary
      file and returned.

    <Returns>
      A 'tuf.util.TempFile' file-like object containing the metadata.
    """

    file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', remote_filename,
                                                   self.mirrors)
    # file_mirror (URL): error (Exception)
    file_mirror_errors = {}
    file_object = None

    for file_mirror in file_mirrors:
      try:
        file_object = tuf.download.unsafe_download(file_mirror,
                                                   upperbound_filelength)

        if compression_algorithm is not None:
          logger.info('Decompressing ' + str(file_mirror))
          file_object.decompress_temp_file_object(compression_algorithm)
        
        else:
          logger.info('Not decompressing ' + str(file_mirror))
        
        # Verify 'file_object' according to the callable function.
        # 'file_object' is also verified if decompressed above (i.e., the
        # uncompressed version).
        metadata_signable = \
          tuf.util.load_json_string(file_object.read().decode('utf-8'))
       
        # If the version number is unspecified, ensure that the version number
        # downloaded is greater than the currently trusted version number for
        # 'metadata_role'.
        version_downloaded = metadata_signable['signed']['version'] 
        
        if expected_version is not None:
          # Verify that the downloaded version matches the version expected by
          # the caller.
          if version_downloaded != expected_version:
            message = \
              'Downloaded version number: ' + repr(version_downloaded) + '.' \
              ' Version number MUST be: ' + repr(expected_version)
            raise tuf.BadVersionNumberError(message) 
         
        # The caller does not know which version to download.  Verify that the
        # downloaded version is at least greater than the one locally available.
        else:
          # Verify that the version number of the locally stored
          # 'timestamp.json', if available, is less than what was downloaded.
          # Otherwise, accept the new timestamp with version number
          # 'version_downloaded'.
          logger.info('metadata_role: ' + repr(metadata_role)) 
          try:
            current_version = \
              self.metadata['current'][metadata_role]['version']
              
            if version_downloaded < current_version:
              raise tuf.ReplayedMetadataError(metadata_role, version_downloaded,
                                              current_version)
          
          except KeyError:
            logger.info(metadata_role + ' not available locally.')

        self._verify_uncompressed_metadata_file(file_object, metadata_role)

      except Exception as exception:
        # Remember the error from this mirror, and "reset" the target file.
        logger.exception('Update failed from ' + file_mirror + '.')
        file_mirror_errors[file_mirror] = exception
        file_object = None
      
      else:
        break

    if file_object:
      return file_object
    
    else:
      logger.error('Failed to update {0} from all mirrors: {1}'.format(
                       remote_filename, file_mirror_errors))
      raise tuf.NoWorkingMirrorError(file_mirror_errors)





  def _safely_get_metadata_file(self, metadata_role, metadata_filepath,
                                uncompressed_fileinfo,
                                compression=None, compressed_fileinfo=None):
    """
    <Purpose>
      Non-public method that safely downloads a metadata file up to a certain
      length, and checks its hashes thereafter.

    <Arguments>
      metadata_role:
        The role name of the metadata (e.g., 'root', 'targets',
        'targets/linux/x86').

      metadata_filepath:
        The metadata filepath (i.e., relative to the repository metadata
        directory).
      
      uncompressed_fileinfo:
        The trusted file length and hashes of the uncompressed version of the 
        metadata file.  Should be 'tuf.formats.FILEINFO_SCHEMA'.

      compression:
        The name of the compression algorithm (e.g., 'gzip'), if the metadata
        file is compressed. 
        
      compressed_fileinfo:
        The fileinfo of the metadata file, if it is compressed.  Should be
        'tuf.formats.FILEINFO_SCHEMA'.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The metadata file is downloaded from all known repository mirrors in the
      worst case. If a valid copy of the metadata file is found, it is stored
      in a temporary file and returned.

    <Returns>
      A 'tuf.util.TempFile' file-like object containing the metadata.
    """
    
    # Store file length and hashes of the uncompressed version metadata.
    # The uncompressed version is always verified.
    uncompressed_file_length = uncompressed_fileinfo['length']
    uncompressed_file_hashes = uncompressed_fileinfo['hashes']
    download_file_length = uncompressed_file_length
    
    # Store the file length and hashes of the compressed version of the
    # metadata, if compressions is set.
    if compression and compressed_fileinfo:
      compressed_file_length = compressed_fileinfo['length']
      compressed_file_hashes = compressed_fileinfo['hashes']
      download_file_length = compressed_file_length
    
    def safely_verify_uncompressed_metadata_file(metadata_file_object):
      self._hard_check_file_length(metadata_file_object,
                                   uncompressed_file_length)
      self._check_hashes(metadata_file_object, uncompressed_file_hashes)
      self._verify_uncompressed_metadata_file(metadata_file_object,
                                              metadata_role)

    def safely_verify_compressed_metadata_file(metadata_file_object):
      self._hard_check_file_length(metadata_file_object, compressed_file_length) 
      self._check_hashes(metadata_file_object, compressed_file_hashes)

    if compression is None:
      safely_verify_compressed_metadata_file = None
    
    return self._get_file(metadata_filepath,
                          safely_verify_uncompressed_metadata_file, 'meta',
                          download_file_length, compression,
                          safely_verify_compressed_metadata_file,
                          download_safely=True)





  # TODO: Instead of the more fragile 'download_safely' switch, unroll the
  # function into two separate ones: one for "safe" download, and the other one
  # for "unsafe" download? This should induce safer and more readable code.
  def _get_file(self, filepath, verify_file_function, file_type,
                file_length, compression=None,
                verify_compressed_file_function=None, download_safely=True):
    """
    <Purpose>
      Non-public method that tries downloading, up to a certain length, a
      metadata or target file from a list of known mirrors. As soon as the first
      valid copy of the file is found, the rest of the mirrors will be skipped.

    <Arguments>
      filepath:
        The relative metadata or target filepath.

      verify_file_function:
        A callable function that expects a 'tuf.util.TempFile' file-like object
        and raises an exception if the file is invalid.  Target files and
        uncompressed versions of metadata may be verified with
        'verify_file_function'.

      file_type:
        Type of data needed for download, must correspond to one of the strings
        in the list ['meta', 'target'].  'meta' for metadata file type or
        'target' for target file type.  It should correspond to the
        'tuf.formats.NAME_SCHEMA' format.

      file_length:
        The expected length, or upper bound, of the target or metadata file to
        be downloaded.

      compression:
        The name of the compression algorithm (e.g., 'gzip'), if the metadata
        file is compressed. 
     
      verify_compressed_file_function:
        If compression is specified, in the case of metadata files, this
        callable function may be set to perform verification of the compressed
        version of the metadata file.  Decompressed metadata is also verified. 

      download_safely:
        A boolean switch to toggle safe or unsafe download of the file.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The metadata could not be fetched. This is raised only when all known
        mirrors failed to provide a valid copy of the desired metadata file.

    <Side Effects>
      The file is downloaded from all known repository mirrors in the worst
      case. If a valid copy of the file is found, it is stored in a temporary
      file and returned.

    <Returns>
      A 'tuf.util.TempFile' file-like object containing the metadata or target.
    """

    file_mirrors = tuf.mirrors.get_list_of_mirrors(file_type, filepath,
                                                   self.mirrors)
    # file_mirror (URL): error (Exception)
    file_mirror_errors = {}
    file_object = None

    for file_mirror in file_mirrors:
      try:
        if download_safely:
          file_object = tuf.download.safe_download(file_mirror,
                                                   file_length)
        else:
          file_object = tuf.download.unsafe_download(file_mirror,
                                                     file_length)

        if compression is not None:
          if verify_compressed_file_function is not None: 
            verify_compressed_file_function(file_object)  
          logger.info('Decompressing ' + str(file_mirror))
          file_object.decompress_temp_file_object(compression)
        
        else:
          logger.info('Not decompressing ' + str(file_mirror))
        
        # Verify 'file_object' according to the callable function.
        # 'file_object' is also verified if decompressed above (i.e., the
        # uncompressed version).
        verify_file_function(file_object)

      except Exception as exception:
        # Remember the error from this mirror, and "reset" the target file.
        logger.exception('Update failed from ' + file_mirror + '.')
        file_mirror_errors[file_mirror] = exception
        file_object = None
      
      else:
        break

    if file_object:
      return file_object
    
    else:
      logger.error('Failed to update {0} from all mirrors: {1}'.format(
                   filepath, file_mirror_errors))
      raise tuf.NoWorkingMirrorError(file_mirror_errors)





  def _update_metadata(self, metadata_role, upperbound_filelength, version=None,
                       compression_algorithm=None):
    """
    <Purpose>
      Non-public method that downloads, verifies, and 'installs' the metadata
      belonging to 'metadata_role'.  Calling this method implies the metadata
      has been updated by the repository and thus needs to be re-downloaded.
      The current and previous metadata stores are updated if the newly
      downloaded metadata is successfully downloaded and verified.
   
    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.
     
      upperbound_filelength:
        The expected length, or upper bound, of the metadata file to be
        downloaded.

      version:
        The expected and required version number of the 'metadata_role' file
        downloaded.  'expected_version' is an integer.
      
      compression_algorithm:
        A string designating the compression type of 'metadata_role'.
        The 'snapshot' metadata file may be optionally downloaded and stored in
        compressed form.  Currently, only metadata files compressed with 'gzip'
        are considered.  Any other string is ignored.

    <Exceptions>
      tuf.NoWorkingMirrorError:
        The metadata cannot be updated. This is not specific to a single
        failure but rather indicates that all possible ways to update the
        metadata have been tried and failed.

    <Side Effects>
      The metadata file belonging to 'metadata_role' is downloaded from a
      repository mirror.  If the metadata is valid, it is stored in the 
      metadata store.

    <Returns>
      None.
    """

    # Construct the metadata filename as expected by the download/mirror modules.
    metadata_filename = metadata_role + '.json'
    uncompressed_metadata_filename = metadata_filename
   
    # The 'snapshot' or Targets metadata may be compressed.  Add the appropriate
    # extension to 'metadata_filename'. 
    if compression_algorithm == 'gzip':
      metadata_filename = metadata_filename + '.gz'

    # Attempt a file download from each mirror until the file is downloaded and
    # verified.  If the signature of the downloaded file is valid, proceed,
    # otherwise log a warning and try the next mirror.  'metadata_file_object'
    # is the file-like object returned by 'download.py'.  'metadata_signable'
    # is the object extracted from 'metadata_file_object'.  Metadata saved to
    # files are regarded as 'signable' objects, conformant to
    # 'tuf.formats.SIGNABLE_SCHEMA'.
    #
    # Some metadata (presently timestamp) will be downloaded "unsafely", in the
    # sense that we can only estimate its true length and know nothing about
    # its version.  This is because not all metadata will have other metadata
    # for it; otherwise we will have an infinite regress of metadata signing
    # for each other. In this case, we will download the metadata up to the
    # best length we can get for it, not request a specific version, but
    # perform the rest of the checks (e.g., signature verification).
    #
    # Note also that we presently support decompression of only "safe"
    # metadata, but this is easily extend to "unsafe" metadata as well as
    # "safe" targets.
   
    remote_filename = metadata_filename
    filename_version = ''

    if self.consistent_snapshot:
      filename_version = version
      dirname, basename = os.path.split(remote_filename)
      remote_filename = os.path.join(dirname, str(filename_version) + '.' + basename)
   
    logger.info('Verifying ' + repr(metadata_role) + '.  Requesting version: ' + repr(version))
    metadata_file_object = \
      self._get_metadata_file(metadata_role, remote_filename,
                              upperbound_filelength, version,
                              compression_algorithm)

    # The metadata has been verified. Move the metadata file into place.
    # First, move the 'current' metadata file to the 'previous' directory
    # if it exists.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    current_filepath = os.path.abspath(current_filepath)
    tuf.util.ensure_parent_dir(current_filepath)
    
    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filename)
    previous_filepath = os.path.abspath(previous_filepath)
    
    if os.path.exists(current_filepath):
      # Previous metadata might not exist, say when delegations are added.
      tuf.util.ensure_parent_dir(previous_filepath)
      shutil.move(current_filepath, previous_filepath)

    # Next, move the verified updated metadata file to the 'current' directory.
    # Note that the 'move' method comes from tuf.util's TempFile class.
    # 'metadata_file_object' is an instance of tuf.util.TempFile.
    metadata_signable = \
      tuf.util.load_json_string(metadata_file_object.read().decode('utf-8'))
    if compression_algorithm == 'gzip':
      current_uncompressed_filepath = \
        os.path.join(self.metadata_directory['current'],
                     uncompressed_metadata_filename)
      current_uncompressed_filepath = \
        os.path.abspath(current_uncompressed_filepath)
      metadata_file_object.move(current_uncompressed_filepath)
    
    else:
      metadata_file_object.move(current_filepath)

    # Extract the metadata object so we can store it to the metadata store.
    # 'current_metadata_object' set to 'None' if there is not an object
    # stored for 'metadata_role'.
    updated_metadata_object = metadata_signable['signed']
    current_metadata_object = self.metadata['current'].get(metadata_role)

    # Finally, update the metadata and fileinfo stores, and rebuild the
    # key and role info for the top-level roles if 'metadata_role' is root.
    # Rebuilding the the key and role info is required if the newly-installed
    # root metadata has revoked keys or updated any top-level role information.
    logger.debug('Updated ' + repr(current_filepath) + '.')
    self.metadata['previous'][metadata_role] = current_metadata_object
    self.metadata['current'][metadata_role] = updated_metadata_object
    self._update_versioninfo(uncompressed_metadata_filename)

    # Ensure the role and key information of the top-level roles is also updated
    # according to the newly-installed Root metadata.
    if metadata_role == 'root':
      self._rebuild_key_and_role_db()
      self.consistent_snapshot = updated_metadata_object['consistent_snapshot']





  def _update_metadata_via_fileinfo(self, metadata_role, uncompressed_fileinfo,
                         compression=None, compressed_fileinfo=None):
      """
      <Purpose>
        Non-public method that downloads, verifies, and 'installs' the metadata
        belonging to 'metadata_role'.  Calling this method implies the metadata
        has been updated by the repository and thus needs to be re-downloaded.
        The current and previous metadata stores are updated if the newly
        downloaded metadata is successfully downloaded and verified.
     
      <Arguments>
        metadata_role:
          The name of the metadata. This is a role name and should not end
          in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.
        
        uncompressed_fileinfo:
          A dictionary containing length and hashes of the uncompressed metadata
          file.
          
          Example:
            {"hashes": {"sha256": "3a5a6ec1f353...dedce36e0"}, 
             "length": 1340}
          
        compression:
          A string designating the compression type of 'metadata_role'.
          The 'snapshot' metadata file may be optionally downloaded and stored in
          compressed form.  Currently, only metadata files compressed with 'gzip'
          are considered.  Any other string is ignored.
        
        compressed_fileinfo:
          A dictionary containing length and hashes of the compressed metadata
          file.
          
          Example:
            
            {"hashes": {"sha256": "3a5a6ec1f353...dedce36e0"}, 
             "length": 1340}
      
      <Exceptions>
        tuf.NoWorkingMirrorError:
          The metadata cannot be updated. This is not specific to a single
          failure but rather indicates that all possible ways to update the
          metadata have been tried and failed.
      
      <Side Effects>
        The metadata file belonging to 'metadata_role' is downloaded from a
        repository mirror.  If the metadata is valid, it is stored in the 
        metadata store.
      
      <Returns>
        None.
      """

      # Construct the metadata filename as expected by the download/mirror modules.
      metadata_filename = metadata_role + '.json'
      uncompressed_metadata_filename = metadata_filename
     
      # The 'snapshot' or Targets metadata may be compressed.  Add the appropriate
      # extension to 'metadata_filename'. 
      if compression == 'gzip':
        metadata_filename = metadata_filename + '.gz'

      # Attempt a file download from each mirror until the file is downloaded and
      # verified.  If the signature of the downloaded file is valid, proceed,
      # otherwise log a warning and try the next mirror.  'metadata_file_object'
      # is the file-like object returned by 'download.py'.  'metadata_signable'
      # is the object extracted from 'metadata_file_object'.  Metadata saved to
      # files are regarded as 'signable' objects, conformant to
      # 'tuf.formats.SIGNABLE_SCHEMA'.
      #
      # Some metadata (presently timestamp) will be downloaded "unsafely", in the
      # sense that we can only estimate its true length and know nothing about
      # its hashes.  This is because not all metadata will have other metadata
      # for it; otherwise we will have an infinite regress of metadata signing
      # for each other. In this case, we will download the metadata up to the
      # best length we can get for it, not check its hashes, but perform the rest
      # of the checks (e.g signature verification).
      #
      # Note also that we presently support decompression of only "safe"
      # metadata, but this is easily extend to "unsafe" metadata as well as
      # "safe" targets.
      
      if metadata_role == 'timestamp':
        metadata_file_object = \
          self._unsafely_get_metadata_file(metadata_role, metadata_filename,
                                           uncompressed_fileinfo,
                                           compression, compressed_fileinfo)
      
      elif metadata_role == 'root' and not len(uncompressed_fileinfo['hashes']):
        metadata_file_object = \
          self._unsafely_get_metadata_file(metadata_role, metadata_filename,
                                           uncompressed_fileinfo,
                                           compression, compressed_fileinfo)
      
      else:
        remote_filename = metadata_filename
        if self.consistent_snapshot:
          if compression:
            filename_digest = \
              random.choice(list(compressed_fileinfo['hashes'].values()))
          
          else:
            filename_digest = \
              random.choice(list(uncompressed_fileinfo['hashes'].values()))
          dirname, basename = os.path.split(remote_filename)
          remote_filename = os.path.join(dirname, filename_digesti + '.' + basename)

        metadata_file_object = \
          self._safely_get_metadata_file(metadata_role, remote_filename,
                                         uncompressed_fileinfo,
                                         compression, compressed_fileinfo)

      # The metadata has been verified. Move the metadata file into place.
      # First, move the 'current' metadata file to the 'previous' directory
      # if it exists.
      current_filepath = os.path.join(self.metadata_directory['current'],
                                      metadata_filename)
      current_filepath = os.path.abspath(current_filepath)
      tuf.util.ensure_parent_dir(current_filepath)
      
      previous_filepath = os.path.join(self.metadata_directory['previous'],
                                       metadata_filename)
      previous_filepath = os.path.abspath(previous_filepath)
      
      if os.path.exists(current_filepath):
        # Previous metadata might not exist, say when delegations are added.
        tuf.util.ensure_parent_dir(previous_filepath)
        shutil.move(current_filepath, previous_filepath)

      # Next, move the verified updated metadata file to the 'current' directory.
      # Note that the 'move' method comes from tuf.util's TempFile class.
      # 'metadata_file_object' is an instance of tuf.util.TempFile.
      metadata_signable = tuf.util.load_json_string(metadata_file_object.read().decode('utf-8'))
      if compression == 'gzip':
        current_uncompressed_filepath = \
          os.path.join(self.metadata_directory['current'],
                       uncompressed_metadata_filename)
        current_uncompressed_filepath = \
          os.path.abspath(current_uncompressed_filepath)
        metadata_file_object.move(current_uncompressed_filepath)
      
      else:
        metadata_file_object.move(current_filepath)

      # Extract the metadata object so we can store it to the metadata store.
      # 'current_metadata_object' set to 'None' if there is not an object
      # stored for 'metadata_role'.
      updated_metadata_object = metadata_signable['signed']
      current_metadata_object = self.metadata['current'].get(metadata_role)

      # Finally, update the metadata and fileinfo stores, and rebuild the
      # key and role info for the top-level roles if 'metadata_role' is root.
      # Rebuilding the the key and role info is required if the newly-installed
      # root metadata has revoked keys or updated any top-level role information.
      logger.debug('Updated '+repr(current_filepath)+'.')
      self.metadata['previous'][metadata_role] = current_metadata_object
      self.metadata['current'][metadata_role] = updated_metadata_object
      self._update_fileinfo(uncompressed_metadata_filename)

      # Ensure the role and key information of the top-level roles is also updated
      # according to the newly-installed Root metadata.
      if metadata_role == 'root':
        self._rebuild_key_and_role_db()
        self.consistent_snapshot = updated_metadata_object['consistent_snapshot']





  def _update_metadata_if_changed(self, metadata_role,
                                  referenced_metadata='snapshot'):
    """
    <Purpose>
      Non-public method that updates the metadata for 'metadata_role' if it has
      changed.  With the exception of the 'timestamp' role, all the top-level
      roles are updated by this method.  The 'timestamp' role is always
      downloaded from a mirror without first checking if it has been updated; it
      is updated in refresh() by calling _update_metadata('timestamp').  This
      method is also called for delegated role metadata, which are referenced by
      'snapshot'.
        
      If the metadata needs to be updated but an update cannot be obtained,
      this method will delete the file (with the exception of the root
      metadata, which never gets removed without a replacement).

      Due to the way in which metadata files are updated, it is expected that
      'referenced_metadata' is not out of date and trusted.  The refresh()
      method updates the top-level roles in 'timestamp -> snapshot ->
      root -> targets' order.  For delegated metadata, the parent role is
      updated before the delegated role.  Taking into account that
      'referenced_metadata' is updated and verified before 'metadata_role',
      this method determines if 'metadata_role' has changed by checking
      the 'meta' field of the newly updated 'referenced_metadata'.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'unclaimed'.

      referenced_metadata:
        This is the metadata that provides the role information for
        'metadata_role'.  For the top-level roles, the 'snapshot' role
        is the referenced metadata for the 'root', and 'targets' roles.
        The 'timestamp' metadata is always downloaded regardless.  In
        other words, it is updated by calling _update_metadata('timestamp')
        and not by this method.  The referenced metadata for 'snapshot'
        is 'timestamp'.  See refresh().
        
    <Exceptions>
      tuf.NoWorkingMirrorError:
        If 'metadata_role' could not be downloaded after determining that it had
        changed.
        
      tuf.RepositoryError:
        If the referenced metadata is missing.

    <Side Effects>
      If it is determined that 'metadata_role' has been updated, the metadata
      store (i.e., self.metadata) is updated with the new metadata and the
      affected stores modified (i.e., the previous metadata store is updated).
      If the metadata is 'targets' or a delegated targets role, the role
      database is updated with the new information, including its delegated
      roles.

    <Returns>
      None.
    """
        
    uncompressed_metadata_filename = metadata_role + '.json'
    expected_versioninfo = None
    expected_fileinfo = None

    # Ensure the referenced metadata has been loaded.  The 'root' role may be
    # updated without having 'snapshot' available.  
    if referenced_metadata not in self.metadata['current']:
      raise tuf.RepositoryError('Cannot update ' + repr(metadata_role) +
        ' because ' + referenced_metadata + ' is missing.')
    
    # The referenced metadata has been loaded.  Extract the new versioninfo for
    # 'metadata_role' from it. 
    else:
      logger.debug(repr(metadata_role) + ' referenced in ' +
        repr(referenced_metadata)+ '.  ' + repr(metadata_role) +
        ' may be updated.')

    if metadata_role in ['root', 'snapshot']:
      # Extract the fileinfo of the uncompressed version of 'metadata_role'.
      expected_fileinfo = self.metadata['current'][referenced_metadata] \
                                       ['meta'] \
                                       [uncompressed_metadata_filename]

      # Simply return if the metadata for 'metadata_role' has not been updated,
      # according to the uncompressed metadata provided by the referenced
      # metadata.  The metadata is considered updated if its fileinfo has
      # changed.
      if not self._fileinfo_has_changed(uncompressed_metadata_filename,
                                        expected_fileinfo):
        logger.info(repr(uncompressed_metadata_filename) + ' up-to-date.')
        
        # Since we have not downloaded a new version of this metadata, we
        # should check to see if our local version is stale and notify the user
        # if so. This raises tuf.ExpiredMetadataError if the metadata we
        # have is expired. Resolves issue #322.
        self._ensure_not_expired(self.metadata['current'][metadata_role],
                                 metadata_role)

        return

    # The version number is inspected instead for all other roles.  The
    # metadata is considered updated if its version number is strictly greater
    # than its currently trusted version number.
    else:
      expected_versioninfo = self.metadata['current'][referenced_metadata] \
                                          ['meta'] \
                                          [uncompressed_metadata_filename]
      
      if not self._versioninfo_has_been_updated(uncompressed_metadata_filename,
                                                expected_versioninfo):
        logger.info(repr(uncompressed_metadata_filename) + ' up-to-date.')
        
        self._ensure_not_expired(self.metadata['current'][metadata_role],
                                 metadata_role)
        
        return
    
    logger.debug('Metadata ' + repr(uncompressed_metadata_filename) + ' has changed.')

    # There might be a compressed version of 'snapshot.json' or Targets
    # metadata available for download.  Check the 'meta' field of
    # 'referenced_metadata' to see if it is listed when 'metadata_role'
    # is 'snapshot'.  The full rolename for delegated Targets metadata
    # must begin with 'targets/'.  The snapshot role lists all the Targets
    # metadata available on the repository, including any that may be in
    # compressed form.
    #
    # In addition to validating the fileinfo (i.e., file lengths and hashes)
    # of the uncompressed metadata, the compressed version is also verified to
    # match its respective fileinfo.  Verifying the compressed fileinfo ensures
    # untrusted data is not decompressed prior to verifying hashes, or
    # decompressing a file that may be invalid or partially intact.
    compression = None

    # Check for the availability of compressed versions of 'snapshot.json',
    # 'targets.json', and delegated Targets (that also start with 'targets').
    # For 'targets.json' and delegated metadata, 'referenced_metata'
    # should always be 'snapshot'.  'snapshot.json' specifies all roles
    # provided by a repository, including their version numbers.
    if metadata_role == 'snapshot' or metadata_role.startswith('targets'):
      if 'gzip' in self.metadata['current']['root']['compression_algorithms']:
        compression = 'gzip'
        gzip_metadata_filename = uncompressed_metadata_filename + '.gz'
        logger.debug('Compressed version of ' +
          repr(uncompressed_metadata_filename) + ' is available at ' +
          repr(gzip_metadata_filename) + '.')
      
      else:
        logger.debug('Compressed version of ' +
          repr(uncompressed_metadata_filename) + ' not available.')

    # The file lengths of metadata are unknown, only their version numbers are
    # known.  Set an upper limit for the length of the downloaded file for each
    # expected role.  Note: The Timestamp role is not updated via this
    # function.
    if metadata_role == 'snapshot': 
      upperbound_filelength = tuf.conf.DEFAULT_SNAPSHOT_REQUIRED_LENGTH
    
    elif metadata_role == 'root':
      upperbound_filelength = tuf.conf.DEFAULT_ROOT_REQUIRED_LENGTH
      
    # The metadata is considered Targets (or delegated Targets metadata).
    else:
      upperbound_filelength = tuf.conf.DEFAULT_TARGETS_REQUIRED_LENGTH
    
    try:
      if metadata_role in ['root', 'snapshot']:
        self._update_metadata_via_fileinfo(metadata_role, expected_fileinfo, compression)
     
      # Update all other metadata by way of version number.
      else:
        self._update_metadata(metadata_role, upperbound_filelength,
                              expected_versioninfo['version'], compression)

    except:
      # The current metadata we have is not current but we couldn't get new
      # metadata. We shouldn't use the old metadata anymore.  This will get rid
      # of in-memory knowledge of the role and delegated roles, but will leave
      # delegated metadata files as current files on disk.
      # 
      # TODO: Should we get rid of the delegated metadata files?  We shouldn't
      # need to, but we need to check the trust implications of the current
      # implementation.
      self._delete_metadata(metadata_role)
      logger.error('Metadata for ' + repr(metadata_role) + ' cannot be updated.')
      raise
    
    else:
      # We need to import the delegated roles of 'metadata_role', since its
      # list of delegations might have changed from what was previously
      # loaded..
      # TODO: Should we remove the keys of the delegated roles?
      self._import_delegations(metadata_role)





  def _versioninfo_has_been_updated(self, metadata_filename, new_versioninfo):
    """
    <Purpose>
      Non-public method that determines whether the current versioninfo of
      'metadata_filename' is less than 'new_versioninfo' (i.e., the version
      number has been incremented).  The 'new_versioninfo' argument should be
      extracted from the latest copy of the metadata that references
      'metadata_filename'.  Example: 'root.json' would be referenced by
      'snapshot.json'.
        
      'new_versioninfo' should only be 'None' if this is for updating
      'root.json' without having 'snapshot.json' available.

    <Arguments>
      metadadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

      new_versioninfo:
        A dict object representing the new file information for
        'metadata_filename'.  'new_versioninfo' may be 'None' when
        updating 'root' without having 'snapshot' available.  This
        dict conforms to 'tuf.formats.VERSIONINFO_SCHEMA' and has
        the form:
        
        {'version': 288}
        
    <Exceptions>
      None.

    <Side Effects>
      If there is no versioninfo currently loaded for 'metadata_filename', try
      to load it.

    <Returns>
      Boolean.  True if the versioninfo has changed, False otherwise.
    """
   
    # If there is no versioninfo currently stored for 'metadata_filename',
    # try to load the file, calculate the versioninfo, and store it.
    if metadata_filename not in self.versioninfo:
      self._update_versioninfo(metadata_filename)

    # Return true if there is no versioninfo for 'metadata_filename'.
    # 'metadata_filename' is not in the 'self.versioninfo' store
    # and it doesn't exist in the 'current' metadata location.
    if self.versioninfo[metadata_filename] is None:
      return True

    current_versioninfo = self.versioninfo[metadata_filename]

    if new_versioninfo['version'] > current_versioninfo['version']:
      return True
    
    else:
      return False





  def _update_versioninfo(self, metadata_filename):
    """
    <Purpose>
      Non-public method that updates the 'self.versioninfo' entry for the
      metadata belonging to 'metadata_filename'.  If the current metadata for
      'metadata_filename' cannot be loaded, set its 'versioninfo' to 'None' to
      signal that it is not in 'self.versioninfo' AND it also doesn't exist
      locally.

    <Arguments>
      metadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.

    <Exceptions>
      None.

    <Side Effects>
      The version number of 'metadata_filename' is calculated and stored in its
      corresponding entry in 'self.versioninfo'.

    <Returns>
      None.
    """
        
    # In case we delayed loading the metadata and didn't do it in
    # __init__ (such as with delegated metadata), then get the version 
    # info now.
       
    # Save the path to the current metadata file for 'metadata_filename'.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    # If the path is invalid, simply return and leave versioninfo unset.
    if not os.path.exists(current_filepath):
      self.versioninfo[metadata_filename] = None
      return
   
    # Extract the version information from the trusted snapshot role and save
    # it to the 'self.versioninfo' store.
    if metadata_filename == 'timestamp.json':
      trusted_versioninfo = \
        self.metadata['current']['timestamp']['version']

    # When updating snapshot.json, the client either (1) has a copy of
    # snapshot.json, or (2) is in the process of obtaining it by first
    # downloading timestamp.json.  Note: Clients are allowed to have only
    # root.json initially, and perform a refresh of top-level metadata to
    # obtain the remaining roles.
    elif metadata_filename == 'snapshot.json':
      
      # Verify the version number of the currently trusted snapshot.json in
      # snapshot.json itself.  Checking the version number specified in
      # timestamp.json may be greater than the version specified in the
      # client's copy of snapshot.json.
      try:
        timestamp_version_number = self.metadata['current']['snapshot']['version']
        trusted_versioninfo = tuf.formats.make_versioninfo(timestamp_version_number)
      
      except KeyError:
        trusted_versioninfo = \
          self.metadata['current']['timestamp']['meta']['snapshot.json']
      
    else:
      
      try:
        # The metadata file names in 'self.metadata' exclude the role
        # extension.  Strip the '.json' extension when checking if
        # 'metadata_filename' currently exists.
        targets_version_number = \
          self.metadata['current'][metadata_filename[:-len('.json')]]['version']
        trusted_versioninfo = \
          tuf.formats.make_versioninfo(targets_version_number)
      
      except KeyError:
        trusted_versioninfo = \
          self.metadata['current']['snapshot']['meta'][metadata_filename]

    self.versioninfo[metadata_filename] = trusted_versioninfo





  def _fileinfo_has_changed(self, metadata_filename, new_fileinfo):
    """
    <Purpose>
      Non-public method that determines whether the current fileinfo of
      'metadata_filename' differs from 'new_fileinfo'.  The 'new_fileinfo'
      argument should be extracted from the latest copy of the metadata that
      references 'metadata_filename'.  Example: 'root.json' would be referenced
      by 'snapshot.json'.
        
      'new_fileinfo' should only be 'None' if this is for updating 'root.json'
      without having 'snapshot.json' available.
    
    <Arguments>
      metadadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.
      new_fileinfo:
        A dict object representing the new file information for
        'metadata_filename'.  'new_fileinfo' may be 'None' when
        updating 'root' without having 'snapshot' available.  This
        dict conforms to 'tuf.formats.FILEINFO_SCHEMA' and has
        the form:
        
        {'length': 23423
         'hashes': {'sha256': adfbc32343..}}
        
    <Exceptions>
      None.
    
    <Side Effects>
      If there is no fileinfo currently loaded for 'metada_filename',
      try to load it.
    
    <Returns>
      Boolean.  True if the fileinfo has changed, false otherwise.
    """
       
    # If there is no fileinfo currently stored for 'metadata_filename',
    # try to load the file, calculate the fileinfo, and store it.
    if metadata_filename not in self.fileinfo:
      self._update_fileinfo(metadata_filename)

    # Return true if there is no fileinfo for 'metadata_filename'.
    # 'metadata_filename' is not in the 'self.fileinfo' store
    # and it doesn't exist in the 'current' metadata location.
    if self.fileinfo[metadata_filename] is None:
      return True

    current_fileinfo = self.fileinfo[metadata_filename]

    if current_fileinfo['length'] != new_fileinfo['length']:
      return True

    # Now compare hashes. Note that the reason we can't just do a simple
    # equality check on the fileinfo dicts is that we want to support the
    # case where the hash algorithms listed in the metadata have changed
    # without having that result in considering all files as needing to be
    # updated, or not all hash algorithms listed can be calculated on the
    # specific client.
    for algorithm, hash_value in six.iteritems(new_fileinfo['hashes']):
      # We're only looking for a single match. This isn't a security
      # check, we just want to prevent unnecessary downloads.
      if algorithm in current_fileinfo['hashes']: 
        if hash_value == current_fileinfo['hashes'][algorithm]:
          return False

    return True





  def _update_fileinfo(self, metadata_filename):
    """
    <Purpose>
      Non-public method that updates the 'self.fileinfo' entry for the metadata
      belonging to 'metadata_filename'.  If the 'current' metadata for
      'metadata_filename' cannot be loaded, set its fileinfo' to 'None' to
      signal that it is not in the 'self.fileinfo' AND it also doesn't exist
      locally.
    
    <Arguments>
      metadata_filename:
        The metadata filename for the role.  For the 'root' role,
        'metadata_filename' would be 'root.json'.
    
    <Exceptions>
      None.
    
    <Side Effects>
      The file details of 'metadata_filename' is calculated and
      stored in 'self.fileinfo'.
    
    <Returns>
      None.
    """
        
    # In case we delayed loading the metadata and didn't do it in
    # __init__ (such as with delegated metadata), then get the file
    # info now.
       
    # Save the path to the current metadata file for 'metadata_filename'.
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filename)
    # If the path is invalid, simply return and leave fileinfo unset.
    if not os.path.exists(current_filepath):
      self.fileinfo[metadata_filename] = None
      return
   
    # Extract the file information from the actual file and save it
    # to the fileinfo store.
    file_length, hashes = tuf.util.get_file_details(current_filepath)
    metadata_fileinfo = tuf.formats.make_fileinfo(file_length, hashes)
    self.fileinfo[metadata_filename] = metadata_fileinfo







  def _move_current_to_previous(self, metadata_role):
    """
    <Purpose>
      Non-public method that moves the current metadata file for 'metadata_role'
      to the previous directory.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.
    
    <Exceptions>
      None.

    <Side Effects>
     The metadata file for 'metadata_role' is removed from 'current'
     and moved to the 'previous' directory.

    <Returns>
      None.
    """

    # Get the 'current' and 'previous' full file paths for 'metadata_role'
    metadata_filepath = metadata_role + '.json'
    previous_filepath = os.path.join(self.metadata_directory['previous'],
                                     metadata_filepath)
    current_filepath = os.path.join(self.metadata_directory['current'],
                                    metadata_filepath)

    # Remove the previous path if it exists.
    if os.path.exists(previous_filepath):
      os.remove(previous_filepath)

    # Move the current path to the previous path.  
    if os.path.exists(current_filepath):
      tuf.util.ensure_parent_dir(previous_filepath)
      os.rename(current_filepath, previous_filepath)





  def _delete_metadata(self, metadata_role):
    """
    <Purpose>
      Non-public method that removes all (current) knowledge of 'metadata_role'.
      The metadata belonging to 'metadata_role' is removed from the current
      'self.metadata' store and from the role database. The 'root.json' role
      file is never removed.

    <Arguments>
      metadata_role:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.

    <Exceptions>
      None.

    <Side Effects>
      The role database is modified and the metadata for 'metadata_role'
      removed from the 'self.metadata' store.
    
    <Returns>
      None.
    """
      
    # The root metadata role is never deleted without a replacement.
    if metadata_role == 'root':
      return
    
    # Get rid of the current metadata file.
    self._move_current_to_previous(metadata_role)
    
    # Remove knowledge of the role.
    if metadata_role in self.metadata['current']:
      del self.metadata['current'][metadata_role]
    tuf.roledb.remove_role(metadata_role, self.repository_name)





  def _ensure_not_expired(self, metadata_object, metadata_rolename):
    """
    <Purpose>
      Non-public method that raises an exception if the current specified
      metadata has expired.
    
    <Arguments>
      metadata_object:
        The metadata that should be expired, a 'tuf.formats.ANYROLE_SCHEMA'
        object.

      metadata_rolename:
        The name of the metadata. This is a role name and should not end
        in '.json'.  Examples: 'root', 'targets', 'targets/linux/x86'.
    
    <Exceptions>
      tuf.ExpiredMetadataError:
        If 'metadata_rolename' has expired.

    <Side Effects>
      None.

    <Returns>
      None.
    """

    # Extract the expiration time.
    expires = metadata_object['expires']
   
    # If the current time has surpassed the expiration date, raise
    # an exception.  'expires' is in 'tuf.formats.ISO8601_DATETIME_SCHEMA'
    # format (e.g., '1985-10-21T01:22:00Z'.)  Convert it to a unix timestamp and
    # compare it against the current time.time() (also in Unix/POSIX time
    # format, although with microseconds attached.)
    current_time = int(time.time())

    # Generate a user-friendly error message if 'expires' is less than the
    # current time (i.e., a local time.)
    expires_datetime = iso8601.parse_date(expires)
    expires_timestamp = tuf.formats.datetime_to_unix_timestamp(expires_datetime)
    
    if expires_timestamp < current_time:
      message = 'Metadata '+repr(metadata_rolename)+' expired on ' + \
        expires_datetime.ctime() + ' (UTC).'
      logger.error(message)

      raise tuf.ExpiredMetadataError(message)





  def all_targets(self):
    """
    <Purpose> 
      Get a list of the target information for all the trusted targets
      on the repository.  This list also includes all the targets of
      delegated roles.  Targets of the list returned are ordered according
      the trusted order of the delegated roles, where parent roles come before
      children.  The list conforms to 'tuf.formats.TARGETFILES_SCHEMA'
      and has the form:
      
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      None.

    <Exceptions>
      tuf.RepositoryError:
        If the metadata for the 'targets' role is missing from
        the 'snapshot' metadata.

      tuf.UnknownRoleError:
        If one of the roles could not be found in the role database.

    <Side Effects>
      The metadata for target roles is updated and stored.

    <Returns>
     A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'.
    """
    
    # Load the most up-to-date targets of the 'targets' role and all
    # delegated roles.
    self._refresh_targets_metadata(refresh_all_delegated_roles=True)
 
    # Fetch the targets for the 'targets' role.
    all_targets = self._targets_of_role('targets', skip_refresh=True)

    # Fetch the targets of the delegated roles.  get_rolenames returns
    # all roles available on the repository.
    delegated_targets = []
    for role in tuf.roledb.get_rolenames(self.repository_name):
      if role in ['root', 'snapshot', 'targets', 'timestamp']:
        continue
      
      else: 
        delegated_targets.extend(self._targets_of_role(role, skip_refresh=True))
    
    all_targets.extend(delegated_targets)
    
    return all_targets





  def _refresh_targets_metadata(self, rolename='targets',
                                refresh_all_delegated_roles=False):
    """
    <Purpose>
      Non-public method that refreshes the targets metadata of 'rolename'.  If
      'refresh_all_delegated_roles' is True, include all the delegations that
      follow 'rolename'.  The metadata for the 'targets' role is updated in
      refresh() by the _update_metadata_if_changed('targets') call, not here.
      Delegated roles are not loaded when the repository is first initialized.
      They are loaded from disk, updated if they have changed, and stored to
      the 'self.metadata' store by this method.  This method is called by the
      target methods, like all_targets() and targets_of_role().

    <Arguments>
      rolename:
        This is a delegated role name and should not end in '.json'.  Example:
        'unclaimed'.
      
      refresh_all_delegated_roles:
         Boolean indicating if all the delegated roles available in the
         repository (via snapshot.json) should be refreshed. 

    <Exceptions>
      tuf.RepositoryError:
        If the metadata file for the 'targets' role is missing from the
        'snapshot' metadata.

    <Side Effects>
      The metadata for the delegated roles are loaded and updated if they
      have changed.  Delegated metadata is removed from the role database if
      it has expired.

    <Returns>
      None.
    """

    roles_to_update = []
   
    if rolename + '.json' in self.metadata['current']['snapshot']['meta']:
      roles_to_update.append(rolename)
    
    if refresh_all_delegated_roles:
      
      for role in six.iterkeys(self.metadata['current']['snapshot']['meta']):
        # snapshot.json keeps track of root.json, targets.json, and delegated
        # roles (e.g., django.json, unclaimed.json).
        # Remove the 'targets' role because it gets updated when the targets.json
        # file is updated in _update_metadata_if_changed('targets') and root.
        if role.endswith('.json'):
          role = role[:-len('.json')] 
          if role not in ['root', 'targets', rolename]:
            roles_to_update.append(role)
        
        else:
          continue
    
    # If there is nothing to refresh, we are done.
    if not roles_to_update:
      return

    logger.debug('Roles to update: ' + repr(roles_to_update) + '.')

    # Iterate 'roles_to_update', and load and update its metadata file if it
    # has changed.
    for rolename in roles_to_update:
      self._load_metadata_from_file('previous', rolename)
      self._load_metadata_from_file('current', rolename)

      self._update_metadata_if_changed(rolename)





  def _targets_of_role(self, rolename, targets=None, skip_refresh=False):
    """
    <Purpose>
      Non-public method that returns the target information of all the targets
      of 'rolename'.  The returned information is a list conformant to
      'tuf.formats.TARGETFILES_SCHEMA', and has the form:
      
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      rolename:
        This is a role name and should not end in '.json'.  Examples: 'targets',
        'unclaimed'.
      
      targets:
        A list of targets containing target information, conformant to
        'tuf.formats.TARGETFILES_SCHEMA'.

      skip_refresh:
        A boolean indicating if the target metadata for 'rolename'
        should be refreshed.

    <Exceptions>
      tuf.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata for 'rolename' is refreshed if 'skip_refresh' is False.

    <Returns>
      A list of dict objects containing the target information of all the
      targets of 'rolename'.  Conformant to 'tuf.formats.TARGETFILES_SCHEMA'.
    """

    if targets is None:
      targets = []
    
    targets_of_role = list(targets)
    logger.debug('Getting targets of role: ' + repr(rolename) + '.')

    if not tuf.roledb.role_exists(rolename, self.repository_name):
      raise tuf.UnknownRoleError(rolename)

    # We do not need to worry about the target paths being trusted because
    # this is enforced before any new metadata is accepted.
    if not skip_refresh:
      self._refresh_targets_metadata(rolename)
  
    # Do we have metadata for 'rolename'?
    if rolename not in self.metadata['current']:
      logger.debug('No metadata for ' + repr(rolename) + '.'
        '  Unable to determine targets.')
      return []
    
    # Get the targets specified by the role itself.
    for filepath, fileinfo in six.iteritems(self.metadata['current'][rolename]['targets']):
      new_target = {} 
      new_target['filepath'] = filepath 
      new_target['fileinfo'] = fileinfo
      
      targets_of_role.append(new_target)

    return targets_of_role





  def targets_of_role(self, rolename='targets'):
    """
    <Purpose> 
      Return a list of trusted targets directly specified by 'rolename'.
      The returned information is a list conformant to
      'tuf.formats.TARGETFILES_SCHEMA', and has the form:
      
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

      The metadata of 'rolename' is updated if out of date, including the
      metadata of its parent roles (i.e., the minimum roles needed to set the
      chain of trust).

    <Arguments>
      rolename:
        The name of the role whose list of targets are wanted.
        The name of the role should start with 'targets'.
       
    <Exceptions>
      tuf.FormatError:
        If 'rolename' is improperly formatted.
     
      tuf.RepositoryError:
        If the metadata of 'rolename' cannot be updated.

      tuf.UnknownRoleError:
        If 'rolename' is not found in the role database.

    <Side Effects>
      The metadata of updated delegated roles are downloaded and stored.
      
    <Returns>
      A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'. 
    """
      
    # Does 'rolename' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(rolename)

    if not tuf.roledb.role_exists(rolename, self.repository_name):
      raise tuf.UnknownRoleError(rolename)
    
    self._refresh_targets_metadata(rolename)

    return self._targets_of_role(rolename, skip_refresh=True)





  def target(self, target_filepath):
    """
    <Purpose>
      Return the target file information of 'target_filepath', and update its
      corresponding metadata, if necessary.

    <Arguments>    
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      tuf.FormatError:
        If 'target_filepath' is improperly formatted.

      tuf.UnknownTargetError:
        If 'target_filepath' was not found.

      Any other unforeseen runtime exception.
   
    <Side Effects>
      The metadata for updated delegated roles are downloaded and stored.
    
    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETFILE_SCHEMA'.
    """

    # Does 'target_filepath' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.RELPATH_SCHEMA.check_match(target_filepath)
  
    # 'target_filepath' might contain URL encoding escapes.
    # http://docs.python.org/2/library/urllib.html#urllib.unquote
    target_filepath = six.moves.urllib.parse.unquote(target_filepath)

    if not target_filepath.startswith('/'):
      target_filepath = '/' + target_filepath

    # Ensure the client has the most up-to-date version of 'targets.json'.
    # Raise 'tuf.NoWorkingMirrorError' if the changed metadata cannot be
    # successfully downloaded and 'tuf.RepositoryError' if the referenced
    # metadata is missing.  Target methods such as this one are called after the
    # top-level metadata have been refreshed (i.e., updater.refresh()).
    # THIS FUNCTION MUST refresh targets top level metadata.
    # It must then also retain a list of already-refreshed target delegates
    # and pass it around.
    # NOTE that this includes all delegations, which can be time-consuming and
    # is surely inefficient. The prior design updated roles as they were
    # encountered. We can do that in the new design, too, and that should be
    # considered.
    # This may update every delegation for every target we try to validate.
    self._update_metadata_if_changed('targets')
    self._refresh_targets_metadata('targets', refresh_all_delegated_roles=True)
    # (Redundant? I could instead track every role file we update in this
    # recursion and pass it down and up.... That way, we could check it and
    # update it on each call, refreshing whatever metadata is necessary. Ugly,
    # though. Find solution. Also, will this happen repeatedly if multiple
    # targets are to be updated? Inefficient, if so. At the same time, the
    # additional check would mitigate the impact of delaying attacks somewhat.)

    # Get target by looking at roles in order of priority tags, starting with
    # the targets role itself.
    target = self._target('targets', target_filepath)

    # Raise an exception if the target information could not be retrieved.
    if target is None:
      logger.error(target_filepath + ' not found.')
      raise tuf.UnknownTargetError(target_filepath + ' not found.')
    
    # Otherwise, return the found target.
    else:
      return target





  def _is_delegation_relevant_to_target(self, delegation_info,
      target_filepath):
    """
    <Purpose>
      Non-public method. Returns True if the given delegation includes
      restricted paths that match the given target_filepath. That is, returns
      True if the given delegation includes the given target_filepath.
      Else False.

      That is, determines whether the given 'child_role' has been
      delegated the target with the name 'target_filepath'.

      The delegation may be a normal delegation (delegation to a single role)
      or a multi-role delegation.

      TODO: See if util.ensure_all_targets_allowed does anything clever and
      incorporate that here instead.

      TODO: Should the TUF spec restrict the repository to one particular
      algorithm?  Should we allow the repository to specify in the role
      dictionary the algorithm used for these generated hashed paths?

    <Arguments>
      delegation_info:
        An object matching either tuf.formats.ROLE_SCHEMA or
        tuf.formats.MULTI_ROLE_DELEGATION_SCHEMA; that is, either a normal
        delegation (i.e. a role) or a multi-role delegation.

      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.
   
    <Side Effects>
      None.
    
    <Returns>
      If the delegation whose info is provided includes the target with the
      name 'target_filepath', then we return True. Otherwise, we return False.

    """

    # TODO: check argument delegation_info against tuf.formats.ROLE_SCHEMA or
    # tuf.formats.MULTI_ROLE_DELEGATION_SCHEMA

    delegation_paths = delegation_info.get('paths')
    delegation_path_hash_prefixes = delegation_info.get('path_hash_prefixes')
    # A boolean indicator that tell us whether this delegation includeas the
    # target with the name 'target_filepath'.
    delegation_is_relevant = False

    if delegation_path_hash_prefixes is not None:
      target_filepath_hash = self._get_target_hash(target_filepath)
      for delegation_path_hash_prefix in delegation_path_hash_prefixes:
        if target_filepath_hash.startswith(delegation_path_hash_prefix):
          delegation_is_relevant = True
        
        else:
          continue

    elif delegation_paths is not None:
      for delegation_path in delegation_paths:
        # A child role path may be an explicit path or pattern (Unix
        # shell-style wildcards).  The child role 'delegation_name' is added if
        # 'target_filepath' is equal or matches 'delegation_path'.  Explicit
        # filepaths are also added.
        if fnmatch.fnmatch(target_filepath, delegation_path):
          delegation_is_relevant = True

    else:
      # The 'paths' or 'path_hash_prefixes' fields should not be missing,
      # so we raise a format error here in case they are both missing.
      raise tuf.FormatError('Delegation has neither "paths" nor '
          '"path_hash_prefixes". Delegation info: ' + repr(delegation_info))


    if delegation_is_relevant:
      logger.debug('Delegation has restricted path matching target filepath: '
          + repr(target_filepath))

      # TODO: Additional level of verification, calling a new function that
      # verifies that the delegation path was all OK.
      # Pass it something like: "Here's the target, and here's the delegation
      # path I used to validate it. Was that OK?" Else raise error.

    else:
      logger.debug('Delegation does not have restricted path matching the ' +
          'target filepath: ' + repr(target_filepath) +
          '; delegation info follows: ' + str(delegation_info))

    return delegation_is_relevant





  def _target(self, rolename, target_filepath):
    """
    TODO: Docstring
    <Purpose>
      Private funciton providing a recursion implementing the target()
      function's requirements.
      Returns the target info for a target, based on rolename's metadata and
      any of its delegates' metadata.
      Returns None if unable to find target info for the given target_filepath
      under the given role.
      (Replaces _preorder_depth_first_walk and _visit_child_role and handles
      multi-role delegations correctly.)
    """

    target = None
    role_metadata = self.metadata['current'][rolename]
    targets = role_metadata['targets']
    delegations = role_metadata.get('delegations', {})
    child_roles = delegations.get('roles', [])
    multi_role_delegations = delegations.get('multiroledelegations', {})
    max_number_of_delegations = tuf.conf.MAX_NUMBER_OF_DELEGATIONS

    # Base case of the recursion. If info for the target is in this role,
    # return that.
    target = self._get_target_from_targets_role(rolename, targets,
        target_filepath)
    if target is not None:
      logger.debug('Found target in current role '+repr(rolename))
      return target

    # Else, the current role did not have info on the target, so now we explore
    # the current role's delegations, if there are any.
    # We consider the multi-role delegations first: they take precedence per
    # the spec. If a multi-role delegation is delegated a matching path, then
    # we look there before looking at normal delegations that are delegated a
    # matching path.

    # For each multi-role delegation from the parent delegation
    for mrdelegation in multi_role_delegations:

      if not self._is_delegation_relevant_to_target(mrdelegation,
          target_filepath):
        # Delegation does not include paths that match target_filepath.
        logger.debug('Skipping delegation: '+repr(mrdelegation)) # check repr
        continue

      # Else, delegation is relevant to this target. Process this multi-role
      # delegation. Check every one of its required roles for the target. If
      # target info is provided by all of the required roles (or their
      # delegates), and the target info in each is all equal, return that info.
      tentative_target = None
      required_roles = mrdelegation.get('required_roles', [])
      for child_role_name in required_roles:
        logger.debug('Exploring child role '+repr(child_role_name))
        new_tentative_target = self._target(child_role_name, target_filepath)

        if new_tentative_target is None:
          # If any of the required roles don't yield target info, then this
          # multi-role delegation cannot validate the file.
          tentative_target = None
          break

        elif tentative_target is None:
          tentative_target = new_tentative_target

        else:

          if not _target_info_is_equal(
              tentative_target['fileinfo'], new_tentative_target['fileinfo']):
            # If any two of the required roles don't provide the same target
            # info, then this multi-role delegation cannot validate the file.
            # We proceed as if this multi-role delegation had not specified the
            # target info (allowing the backtrack setting to determine whether
            # or not to continue checking any further delegations).
            logger.debug('A multi-role delegation had one or more of its '
                  'required roles specifying the desired target, but at least '
                  'two roles did not provide the same fileinfo. Skipping this '
                  'multi-role delegation.')
            tentative_target = None
            break


      # Check result of looking for target info in the delegated-to roles.
      if tentative_target is not None:
        target = tentative_target
        return target

      if not mrdelegation['backtrack']: # if cutting, return what we have, even if None
        logger.debug('Found no target info, but not backtracking: encountered '
            'cutting (non-backtracking) delegation.')
        return None
      #(else we discard tentative_target by exiting its scope, target unchanged)

    # If we have neither found the target in this role nor in any multi-role
    # delegation from this role, check the normal delegations.
    for child_role in child_roles:
      if not self._is_delegation_relevant_to_target(child_role,
          target_filepath):
        logger.debug('Skipping delegation: '+repr(child_role)) # kinda long
        continue

      target = self._target(child_role['name'], target_filepath)

      if not child_role['backtrack']: # if cutting, return what we have, even if None
        return target
      elif target is not None: #if found valid, stop looking
        break

    return target





  def _get_target_from_targets_role(self, role_name, targets, target_filepath):
    """
    <Purpose>
      Non-public method that determines whether the targets role with the given
      'role_name' has the target with the name 'target_filepath'.

    <Arguments>
      role_name:
        The name of the targets role that we are inspecting.

      targets:
        The targets of the Targets role with the name 'role_name'.
        
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.
   
    <Side Effects>
      None.
    
    <Returns>
      The target information for 'target_filepath', conformant to
      'tuf.formats.TARGETFILE_SCHEMA'.
    """

    target = None

    # Does the current role name have our target?
    logger.debug('Asking role ' + repr(role_name) + ' about target ' +\
      repr(target_filepath))
    
    for filepath, fileinfo in six.iteritems(targets):
      if filepath == target_filepath:
        logger.debug('Found target ' + target_filepath + ' in role ' + role_name)
        target = {'filepath': filepath, 'fileinfo': fileinfo}
        break
      
      else:
        logger.debug('No target ' + target_filepath + ' in role ' + role_name)

    return target





  def _get_target_hash(self, target_filepath, hash_function='sha256'):
    """
    <Purpose>
      Non-public method that computes the hash of 'target_filepath'. This is
      useful in conjunction with the "path_hash_prefixes" attribute in a
      delegated targets role, which tells us which paths it is implicitly
      responsible for.

    <Arguments>
      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

      hash_function:
        The algorithm used by the repository to generate the hashes of the
        target filepaths.  The repository may optionally organize targets into
        hashed bins to ease target delegations and role metadata management.
        The use of consistent hashing allows for a uniform distribution of
        targets into bins. 

    <Exceptions>
      None.
   
    <Side Effects>
      None.
    
    <Returns>
      The hash of 'target_filepath'.
    """

    # Calculate the hash of the filepath to determine which bin to find the 
    # target.  The client currently assumes the repository (i.e., repository
    # tool) uses 'hash_function' to generate hashes and UTF-8.
    digest_object = tuf.hash.digest(hash_function)
    encoded_target_filepath = target_filepath.encode('utf-8')
    digest_object.update(encoded_target_filepath)
    target_filepath_hash = digest_object.hexdigest() 

    return target_filepath_hash





  def remove_obsolete_targets(self, destination_directory):
    """
    <Purpose>
      Remove any files that are in 'previous' but not 'current'.  This makes it
      so if you remove a file from a repository, it actually goes away.  The
      targets for the 'targets' role and all delegated roles are checked.
    
    <Arguments>
      destination_directory:
        The directory containing the target files tracked by TUF.

    <Exceptions>
      tuf.FormatError:
        If 'destination_directory' is improperly formatted.
      
      tuf.RepositoryError:
        If an error occurred removing any files.

    <Side Effects>
      Target files are removed from disk.

    <Returns>
      None.
    """
  
    # Does 'destination_directory' have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    # Iterate through the rolenames and verify whether the 'previous'
    # directory contains a target no longer found in 'current'.
    for role in tuf.roledb.get_rolenames(self.repository_name):
      if role.startswith('targets'):
        if role in self.metadata['previous'] and self.metadata['previous'][role] != None:
          for target in self.metadata['previous'][role]['targets']:
            if target not in self.metadata['current'][role]['targets']:
              # 'target' is only in 'previous', so remove it.
              logger.warning('Removing obsolete file: ' + repr(target) + '.')
              # Remove the file if it hasn't been removed already.
              destination = os.path.join(destination_directory, target.lstrip(os.sep))
              try:
                os.remove(destination)
              
              except OSError as e:
                # If 'filename' already removed, just log it.
                if e.errno == errno.ENOENT:
                  logger.info('File ' + repr(destination) + ' was already removed.')
                
                else:
                  logger.error(str(e))
              
              except Exception as e:
                logger.error(str(e))





  def updated_targets(self, targets, destination_directory):
    """
    <Purpose>
      Return the targets in 'targets' that have changed.  Targets are considered
      changed if they do not exist at 'destination_directory' or the target
      located there has mismatched file properties.

      The returned information is a list conformant to
      'tuf.formats.TARGETFILES_SCHEMA' and has the form:
      
      [{'filepath': 'a/b/c.txt',
        'fileinfo': {'length': 13323,
                     'hashes': {'sha256': dbfac345..}}
       ...]

    <Arguments>
      targets:
        A list of target files.  Targets that come earlier in the list are
        chosen over duplicates that may occur later.

      destination_directory:
        The directory containing the target files.

    <Exceptions>
      tuf.FormatError:
        If the arguments are improperly formatted.

    <Side Effects>
      The files in 'targets' are read and their hashes computed. 

    <Returns>
      A list of targets, conformant to 'tuf.formats.TARGETFILES_SCHEMA'.
    """

    # Do the arguments have the correct format?
    # Raise 'tuf.FormatError' if there is a mismatch.
    tuf.formats.TARGETFILES_SCHEMA.check_match(targets)
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    # Keep track of the target objects and filepaths of updated targets.
    # Return 'updated_targets' and use 'updated_targetpaths' to avoid
    # duplicates.
    updated_targets = []
    updated_targetpaths = []

    for target in targets:
      # Prepend 'destination_directory' to the target's relative filepath (as
      # stored in metadata.)  Verify the hash of 'target_filepath' against
      # each hash listed for its fileinfo.  Note: join() discards
      # 'destination_directory' if 'filepath' contains a leading path separator
      # (i.e., is treated as an absolute path).
      filepath = target['filepath']
      if filepath[0] == '/':
        filepath = filepath[1:]
      target_filepath = os.path.join(destination_directory, filepath)
      
      if target_filepath in updated_targetpaths:
        continue
      
      # Try one of the algorithm/digest combos for a mismatch.  We break
      # as soon as we find a mismatch.
      for algorithm, digest in six.iteritems(target['fileinfo']['hashes']):
        digest_object = None
        try:
          digest_object = tuf.hash.digest_filename(target_filepath,
                                                   algorithm=algorithm)
        
        # This exception would occur if the target does not exist locally. 
        except IOError:
          updated_targets.append(target)
          updated_targetpaths.append(target_filepath)
          break
        
        # The file does exist locally, check if its hash differs. 
        if digest_object.hexdigest() != digest:
          updated_targets.append(target)
          updated_targetpaths.append(target_filepath)
          break
    
    return updated_targets





  def download_target(self, target, destination_directory):
    """
    <Purpose>
      Download 'target' and verify it is trusted.
        
      This will only store the file at 'destination_directory' if the
      downloaded file matches the description of the file in the trusted
      metadata.
    
    <Arguments>
      target:
        The target to be downloaded.  Conformant to
        'tuf.formats.TARGETFILE_SCHEMA'.

      destination_directory:
        The directory to save the downloaded target file.

    <Exceptions>
      tuf.FormatError:
        If 'target' is not properly formatted.

      tuf.NoWorkingMirrorError:
        If a target could not be downloaded from any of the mirrors.

        Although expected to be rare, there might be OSError exceptions (except
        errno.EEXIST) raised when creating the destination directory (if it
        doesn't exist). 

    <Side Effects>
      A target file is saved to the local system.

    <Returns>
      None.
    """

    # Do the arguments have the correct format? 
    # This check ensures the arguments have the appropriate 
    # number of objects and object types, and that all dict
    # keys are properly named.
    # Raise 'tuf.FormatError' if the check fail.
    tuf.formats.TARGETFILE_SCHEMA.check_match(target)
    tuf.formats.PATH_SCHEMA.check_match(destination_directory)

    # Extract the target file information.
    target_filepath = target['filepath']
    trusted_length = target['fileinfo']['length']
    trusted_hashes = target['fileinfo']['hashes']

    # '_get_target_file()' checks every mirror and returns the first target
    # that passes verification.
    target_file_object = self._get_target_file(target_filepath, trusted_length,
                                               trusted_hashes)
   
    # We acquired a target file object from a mirror.  Move the file into place
    # (i.e., locally to 'destination_directory').  Note: join() discards
    # 'destination_directory' if 'target_path' contains a leading path
    # separator (i.e., is treated as an absolute path).
    destination = os.path.join(destination_directory,
                               target_filepath.lstrip(os.sep))
    destination = os.path.abspath(destination)
    target_dirpath = os.path.dirname(destination)
   
    # When attempting to create the leaf directory of 'target_dirpath', ignore
    # any exceptions raised if the root directory already exists.  All other
    # exceptions potentially thrown by os.makedirs() are re-raised.
    # Note: os.makedirs can raise OSError if the leaf directory already exists
    # or cannot be created.
    try:
      os.makedirs(target_dirpath)
    
    except OSError as e:
      if e.errno == errno.EEXIST:
        pass
      
      else:
        raise

    target_file_object.move(destination)







def _validate_metadata_set(metadata_set):
  """
  TODO: Docstring.
  Raises a tuf.Error if metadata_set is not 'current' or 'previous'.
  The metadata dictionary that stores metadata information for the repository
  is separated into 'current' and 'previous' dictionaries. 
  """
  if metadata_set not in ['current', 'previous']:
    raise tuf.Error('Invalid metadata set: ' + repr(metadata_set))





def _target_info_is_equal(info1, info2):
  """
  TODO: Docstring.

  """
  # Check arguments.

  tuf.formats.FILEINFO_SCHEMA.check_match(info1)
  tuf.formats.FILEINFO_SCHEMA.check_match(info2)

  # TODO: Consider adding to schema class functionality the ability to query
  # a schema for all its subfields so that we can check them all (except
  # custom) here....

  for field in ['version', 'length']:
    if info1.get(field, False) != info2.get(field, False):
      return False

  # For each hash type listed in either of the two file info objects,
  # ensure that that hash type is listed in the other and also equal to the
  # other's.
  # There's some defensive coding happening here to avoid making many
  # assumptions about the structure of tuf.formats.FILEINFO_SCHEMA going
  # forward.
  if len(info1.get('hashes', [])) != len(info2.get('hashes', [])):
    logger.debug('Target info objects not equal to each other because '
        'a different number of hashes are listed.')
    return False

  for hashtype in info1.get('hashes', []):

    if hashtype not in info2['hashes']:
      logger.debug('Target info objects not equal to each other because hash '
          'type ' + repr(hashtype) + ' exists in only one of the objects.')
      return False

    if info1['hashes'][hashtype] != info2['hashes'][hashtype]:
      logger.debug('Target info objects not equal to each other because hash '
          'type ' + repr(hashtype) + ' does not match.')
      return False

  return True
