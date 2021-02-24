# Copyright 2020, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client 1.0.0 draft

TODO

"""

#Imports
import os
import logging
import fnmatch

from typing import TextIO, BinaryIO, Dict, Optional

import securesystemslib.exceptions
import securesystemslib.util

import tuf.settings
import tuf.mirrors
import tuf.download
import tuf.exceptions
import tuf.formats

from tuf.client.fetcher import FetcherInterface
from tuf.requests_fetcher import RequestsFetcher
from .metadata_wrapper import (
    RootWrapper,
    SnapshotWrapper,
    TimestampWrapper,
    TargetsWrapper
)

# Globals
logger = logging.getLogger(__name__)

# Classes
class Updater:
    """
    Provides a class that can download target files securely.

    Attributes:
        metadata:

        repository_name:

        mirrors:

        fetcher:

        consistent_snapshot:
    """

    def __init__(
            self, repository_name: str,
            repository_mirrors: Dict,
            fetcher: Optional[FetcherInterface]=None):

        self._repository_name = repository_name
        self._mirrors = repository_mirrors
        self._consistent_snapshot = False
        self._metadata = {'root': {},
                         'timestamp': {},
                         'snapshot': {},
                         'targets': {}}

        if fetcher is None:
            self._fetcher = RequestsFetcher()
        else:
            self._fetcher = fetcher


    def refresh(self) -> None:
        """
        This method downloads, verifies, and loads metadata for the top-level
        roles in a specific order (root -> timestamp -> snapshot -> targets)
        The expiration time for downloaded metadata is also verified.

        The metadata for delegated roles are not refreshed by this method, but
        by the method that returns targetinfo (i.e.,
        get_one_valid_targetinfo()).

        The refresh() method should be called by the client before any target
        requests.
        """

        self._load_root()
        self._load_timestamp()
        self._load_snapshot()
        self._load_targets('targets', 'root')


    def get_one_valid_targetinfo(self, filename: str) -> Dict:
        """
        Returns the target information for a specific file identified by its
        file path.  This target method also downloads the metadata of updated
        targets.
        """
        return self._preorder_depth_first_walk(filename)


    def updated_targets(self, targets: Dict,
                        destination_directory: str) -> Dict:
        """
        After the client has retrieved the target information for those targets
        they are interested in updating, they would call this method to
        determine which targets have changed from those saved locally on disk.
        All the targets that have changed are returns in a list.  From this
        list, they can request a download by calling 'download_target()'.
        """
        # Keep track of the target objects and filepaths of updated targets.
        # Return 'updated_targets' and use 'updated_targetpaths' to avoid
        # duplicates.
        updated_targets = []
        updated_targetpaths = []

        for target in targets:
            # Prepend 'destination_directory' to the target's relative filepath
            # (as stored in metadata.)  Verify the hash of 'target_filepath'
            # against each hash listed for its fileinfo.  Note: join() discards
            # 'destination_directory' if 'filepath' contains a leading path
            # separator (i.e., is treated as an absolute path).
            filepath = target['filepath']
            target_filepath = os.path.join(destination_directory, filepath)

            if target_filepath in updated_targetpaths:
                continue

            # Try one of the algorithm/digest combos for a mismatch.  We break
            # as soon as we find a mismatch.
            for algorithm, digest in target['fileinfo']['hashes'].items():
                digest_object = None
                try:
                    digest_object = securesystemslib.hash.digest_filename(
                        target_filepath, algorithm=algorithm)

                # This exception will occur if the target does not exist
                # locally.
                except securesystemslib.exceptions.StorageError:
                    updated_targets.append(target)
                    updated_targetpaths.append(target_filepath)
                    break

                # The file does exist locally, check if its hash differs.
                if digest_object.hexdigest() != digest:
                    updated_targets.append(target)
                    updated_targetpaths.append(target_filepath)
                    break

        return updated_targets


    def download_target(self, target: Dict, destination_directory: str):
        """
        This method performs the actual download of the specified target.
        The file is saved to the 'destination_directory' argument.
        """

        for temp_obj in self._mirror_target_download(target):
            try:
                self._verify_target_file(temp_obj, target)
                # break? should we break after first successful download?
            except Exception as exception:
                # TODO: do something with exceptions
                raise

        filepath = os.path.join(destination_directory, target['filepath'])
        securesystemslib.util.persist_temp_file(temp_obj, filepath)



    def _mirror_meta_download(
            self, filename: str, upper_length: int) -> TextIO:
        """
        Download metadata file from the list of metadata mirrors
        """
        file_mirrors = tuf.mirrors.get_list_of_mirrors('meta', filename,
            self._mirrors)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = tuf.download.unsafe_download(
                    file_mirror,
                    upper_length,
                    self._fetcher)

                temp_obj.seek(0)
                yield temp_obj

            except Exception as exception:
                file_mirror_errors[file_mirror] = exception

            finally:
                if file_mirror_errors:
                    raise tuf.exceptions.NoWorkingMirrorError(
                        file_mirror_errors)


    def _mirror_target_download(self, fileinfo: str) -> BinaryIO:
        """
        Download target file from the list of target mirrors
        """
        # full_filename = _get_full_name(filename)
        file_mirrors = tuf.mirrors.get_list_of_mirrors(
            'target', fileinfo['filepath'], self._mirrors)

        file_mirror_errors = {}
        for file_mirror in file_mirrors:
            try:
                temp_obj = tuf.download.safe_download(
                    file_mirror,
                    fileinfo['fileinfo']['length'],
                    self._fetcher)

                temp_obj.seek(0)
                yield temp_obj

            except Exception as exception:
                file_mirror_errors[file_mirror] = exception

            finally:
                if file_mirror_errors:
                    raise tuf.exceptions.NoWorkingMirrorError(
                        file_mirror_errors)


    def _get_full_meta_name(self,
                            role: str,
                            extension: str ='.json',
                            version: int = None) -> str:
        """
        Helper method returning full metadata file path given the role name
        and file extension.
        """
        if version is None:
            filename = role + extension
        else:
            filename = str(version) + '.' + role + extension
        return os.path.join(tuf.settings.repositories_directory,
            self._repository_name, 'metadata', 'current', filename)


    def _get_relative_meta_name(
            self, role: str,
            extension: str ='.json',
            version: int = None) -> str:
        """
        Helper method returning full metadata file path given the role name
        and file extension.
        """
        if version is None:
            filename = role + extension
        else:
            filename = str(version) + '.' + role + extension
        return filename


    def  _load_root(self) -> None:
        """
        If metadata file for 'root' role does not exist locally, download it
        over a network, verify it and store it permanently.
        """

        # Load trusted root metadata
        self._metadata['root'] = RootWrapper.from_json_file(
            self._get_full_meta_name('root'))

        # Update the root role
        # 1.1. Let N denote the version number of the trusted
        # root metadata file.
        lower_bound = self._metadata['root']._meta.signed.version
        upper_bound = lower_bound + tuf.settings.MAX_NUMBER_ROOT_ROTATIONS

        verified_root = None
        for next_version in range(lower_bound, upper_bound):
            try:
                mirror_download = self._mirror_meta_download(
                    self._get_relative_meta_name('root', version=next_version),
                    tuf.settings.DEFAULT_ROOT_REQUIRED_LENGTH)

                for temp_obj in mirror_download:
                    try:
                        verified_root = self._verify_root(temp_obj)

                    except Exception as exception:
                        raise

            except tuf.exceptions.NoWorkingMirrorError as exception:
                for mirror_error in exception.mirror_errors.values():
                    if neither_403_nor_404(mirror_error):
                        temp_obj.close()
                        raise

                break

        # Check for a freeze attack. The latest known time MUST be lower
        # than the expiration timestamp in the trusted root metadata file
        try:
            verified_root.expires()
        except Exception:
            temp_obj.close()

        # 1.9. If the timestamp and / or snapshot keys have been rotated,
        # then delete the trusted timestamp and snapshot metadata files.
        if (self._metadata['root'].keys('timestamp') !=
            verified_root.keys('timestamp')):
          # FIXME: use abstract storage
            os.remove(self._get_full_meta_name('timestamp'))
            self._metadata['timestamp'] = {}

        if (self._metadata['root'].keys('snapshot') !=
            verified_root.keys('snapshot')):
          # FIXME: use abstract storage
            os.remove(self._get_full_meta_name('snapshot'))
            self._metadata['snapshot'] = {}

        self._metadata['root'] = verified_root
        # Persist root metadata. The client MUST write the file to non-volatile
        # storage as FILENAME.EXT (e.g. root.json).
        self._metadata['root'].persist(self._get_full_meta_name('root'))

        # 1.10. Set whether consistent snapshots are used as per
        # the trusted root metadata file
        self._consistent_snapshot = \
            self._metadata['root'].signed.consistent_snapshot
        temp_obj.close()





    def _load_timestamp(self) -> None:
        # TODO Check if timestamp exists locally
        for temp_obj in self._mirror_meta_download('timestamp.json',
            tuf.settings.DEFAULT_TIMESTAMP_REQUIRED_LENGTH):
            try:
                verified_tampstamp = self._verify_timestamp(temp_obj)
                # break? should we break after first successful download?
            except Exception as exception:
                # TODO: do something with exceptions
                temp_obj.close()
                raise

        self._metadata['timestamp'] = verified_tampstamp
        # Persist root metadata. The client MUST write the file to
        # non-volatile storage as FILENAME.EXT (e.g. root.json).
        self._metadata['timestamp'].persist(
            self._get_full_meta_name('timestamp.json'))

        temp_obj.close()



    def _load_snapshot(self) -> None:

        try:
            length = self._metadata['timestamp'].snapshot['length']
        except KeyError:
            length = tuf.settings.DEFAULT_SNAPSHOT_REQUIRED_LENGTH

        if self._consistent_snapshot:
            version = self._metadata['timestamp'].snapshot['version']
        else:
            version = None

        #Check if exists locally
        # self.loadLocal('snapshot', snapshotVerifier)
        for temp_obj in self._mirror_meta_download('snapshot.json', length):
            try:
                verified_snapshot = self._verify_snapshot(temp_obj)
                # break? should we break after first successful download?
            except Exception as exception:
                # TODO: do something with exceptions
                temp_obj.close()
                raise

        self._metadata['snapshot'] = verified_snapshot
        # Persist root metadata. The client MUST write the file to
        # non-volatile storage as FILENAME.EXT (e.g. root.json).
        self._metadata['snapshot'].persist(
            self._get_full_meta_name('snapshot.json'))

        temp_obj.close()


    def _load_targets(self, targets_role: str, parent_role: str) -> None:
        try:
            length = self._metadata['snapshot'].role(targets_role)['length']
        except KeyError:
            length = tuf.settings.DEFAULT_TARGETS_REQUIRED_LENGTH

        if self._consistent_snapshot:
            version = self._metadata['snapshot'].role(targets_role)['version']
        else:
            version = None


        #Check if exists locally
        # self.loadLocal('snapshot', targetsVerifier)

        for temp_obj in self._mirror_meta_download(
            targets_role + '.json', length):
            try:
                verified_targets = self._verify_targets(temp_obj,
                    targets_role, parent_role)
                # break? should we break after first successful download?
            except Exception as exception:
                # TODO: do something with exceptions
                temp_obj.close()
                raise
        self._metadata[targets_role] = verified_targets
        # Persist root metadata. The client MUST write the file to
        # non-volatile storage as FILENAME.EXT (e.g. root.json).
        self._metadata[targets_role].persist(
            self._get_full_meta_name(targets_role, extension='.json'))

        temp_obj.close()



    def _verify_root(self, temp_obj: TextIO) -> RootWrapper:

        intermediate_root = RootWrapper.from_json_object(temp_obj)

        # Check for an arbitrary software attack
        trusted_root = self._metadata['root']
        intermediate_root.verify(trusted_root.keys('root'),
                                 trusted_root.threshold('root'))
        intermediate_root.verify(intermediate_root.keys('root'),
                                 intermediate_root.threshold('root'))

        # Check for a rollback attack.
        if intermediate_root.version < trusted_root.version:
            temp_obj.close()
            raise tuf.exceptions.ReplayedMetadataError(
                'root', intermediate_root.version(), trusted_root.version())
        # Note that the expiration of the new (intermediate) root metadata
        # file does not matter yet, because we will check for it in step 1.8.

        return intermediate_root


    def _verify_timestamp(self, temp_obj: TextIO) -> TimestampWrapper:
        intermediate_timestamp = TimestampWrapper.from_json_object(temp_obj)

        # Check for an arbitrary software attack
        trusted_root = self._metadata['root']
        intermediate_timestamp.verify(
            trusted_root.keys('timestamp'),
            trusted_root.threshold('timestamp'))

        # Check for a rollback attack.
        if self._metadata['timestamp']:
            if (intermediate_timestamp.signed.version <=
                self._metadata['timestamp'].version):
                temp_obj.close()
                raise tuf.exceptions.ReplayedMetadataError(
                    'root', intermediate_timestamp.version(),
                    self._metadata['timestamp'].version())

        if self._metadata['snapshot']:
            if (intermediate_timestamp.snapshot.version <=
                self._metadata['timestamp'].snapshot['version']):
                temp_obj.close()
                raise tuf.exceptions.ReplayedMetadataError(
                    'root', intermediate_timestamp.snapshot.version(),
                    self._metadata['snapshot'].version())

        intermediate_timestamp.expires()

        return intermediate_timestamp



    def _verify_snapshot(self, temp_obj: TextIO) -> SnapshotWrapper:

         # Check against timestamp metadata
        if self._metadata['timestamp'].snapshot.get('hash'):
            _check_hashes(temp_obj,
                self._metadata['timestamp'].snapshot.get('hash'))

        intermediate_snapshot = SnapshotWrapper.from_json_object(temp_obj)

        if (intermediate_snapshot.version !=
            self._metadata['timestamp'].snapshot['version']):
            temp_obj.close()
            raise tuf.exceptions.BadVersionNumberError

        # Check for an arbitrary software attack
        trusted_root = self._metadata['root']
        intermediate_snapshot.verify(trusted_root.keys('snapshot'),
                                     trusted_root.threshold('snapshot'))

        # Check for a rollback attack
        if self._metadata['snapshot']:
            for target_role in intermediate_snapshot.signed.meta:
                if (target_role['version'] !=
                    self._metadata['snapshot'].meta[target_role]['version']):
                    temp_obj.close()
                    raise tuf.exceptions.BadVersionNumberError

        intermediate_snapshot.expires()

        return intermediate_snapshot


    def _verify_targets(self,
        temp_obj: TextIO, filename: str, parent_role: str) -> TargetsWrapper:

         # Check against timestamp metadata
        if self._metadata['snapshot'].role(filename).get('hash'):
            _check_hashes(temp_obj,
                self._metadata['snapshot'].targets.get('hash'))

        intermediate_targets = TargetsWrapper.from_json_object(temp_obj)
        if (intermediate_targets.version !=
            self._metadata['snapshot'].role(filename)['version']):
            temp_obj.close()
            raise tuf.exceptions.BadVersionNumberError

        # Check for an arbitrary software attack
        parent_role = self._metadata[parent_role]

        intermediate_targets.verify(parent_role.keys(filename),
                                    parent_role.threshold(filename))

        intermediate_targets.expires()

        return intermediate_targets



    def _verify_target_file(self,
        temp_obj: BinaryIO, targetinfo: Dict) -> None:

        _check_file_length(temp_obj, targetinfo['fileinfo']['length'])
        _check_hashes(temp_obj, targetinfo['fileinfo']['hashes'])



    def _preorder_depth_first_walk(self, target_filepath) -> Dict:

        target = None
        role_names = [('targets', 'root')]
        visited_role_names = set()
        number_of_delegations = tuf.settings.MAX_NUMBER_OF_DELEGATIONS

        # Ensure the client has the most up-to-date version of 'targets.json'.
        # Raise 'tuf.exceptions.NoWorkingMirrorError' if the changed metadata
        # cannot be successfully downloaded and
        # 'tuf.exceptions.RepositoryError' if the referenced metadata is
        # missing.  Target methods such as this one are called after the
        # top-level metadata have been refreshed (i.e., updater.refresh()).
        # self._update_metadata_if_changed('targets')

        # Preorder depth-first traversal of the graph of target delegations.
        while (target is None and
               number_of_delegations > 0 and
               len(role_names) > 0):

            # Pop the role name from the top of the stack.
            role_name, parent_role = role_names.pop(-1)
            self._load_targets(role_name, parent_role)
            # Skip any visited current role to prevent cycles.
            if (role_name, parent_role) in visited_role_names:
                logger.debug(f"Skipping visited current role {role_name}")
                continue

            # The metadata for 'role_name' must be downloaded/updated before
            # its targets, delegations, and child roles can be inspected.
            # self._metadata['current'][role_name] is currently missing.
            # _refresh_targets_metadata() does not refresh 'targets.json', it
            # expects _update_metadata_if_changed() to have already refreshed
            # it, which this function has checked above.
            # self._refresh_targets_metadata(role_name,
            #     refresh_all_delegated_roles=False)

            role_metadata = self._metadata[role_name]
            targets = role_metadata.targets
            target = targets.get(target_filepath)

            # After preorder check, add current role to set of visited roles.
            visited_role_names.add((role_name, parent_role))

            # And also decrement number of visited roles.
            number_of_delegations -= 1
            delegations = role_metadata.delegations
            child_roles = delegations.get('roles', [])

            if target is None:

                child_roles_to_visit = []
                # NOTE: This may be a slow operation if there are many
                # delegated roles.
                for child_role in child_roles:
                    child_role_name = _visit_child_role(
                        child_role, target_filepath)

                    if (child_role['terminating'] and
                        child_role_name is not None):
                        logger.debug('Adding child role ' +
                                    repr(child_role_name))
                        logger.debug('Not backtracking to other roles.')
                        role_names = []
                        child_roles_to_visit.append(
                            (child_role_name, role_name))
                        break

                    if child_role_name is None:
                        logger.debug('Skipping child role ' +
                                    repr(child_role_name))

                    else:
                        logger.debug('Adding child role ' +
                                    repr(child_role_name))
                        child_roles_to_visit.append(
                            (child_role_name, role_name))

                # Push 'child_roles_to_visit' in reverse order of appearance
                # onto 'role_names'.  Roles are popped from the end of
                # the 'role_names' list.
                child_roles_to_visit.reverse()
                role_names.extend(child_roles_to_visit)

            else:
                logger.debug('Found target in current role ' +
                            repr(role_name))

        if (target is None and
            number_of_delegations == 0 and
            len(role_names) > 0):
            logger.debug(repr(len(role_names)) + ' roles left to visit, ' +
                'but allowed to visit at most ' +
                repr(tuf.settings.MAX_NUMBER_OF_DELEGATIONS) + ' delegations.')

        return {'filepath': target_filepath, 'fileinfo': target}






def _visit_child_role(child_role: Dict, target_filepath: str) -> str:
    """
    <Purpose>
      Non-public method that determines whether the given 'target_filepath'
      is an allowed path of 'child_role'.

      Ensure that we explore only delegated roles trusted with the target.  The
      metadata for 'child_role' should have been refreshed prior to this point,
      however, the paths/targets that 'child_role' signs for have not been
      verified (as intended).  The paths/targets that 'child_role' is allowed
      to specify in its metadata depends on the delegating role, and thus is
      left to the caller to verify.  We verify here that 'target_filepath'
      is an allowed path according to the delegated 'child_role'.

      TODO: Should the TUF spec restrict the repository to one particular
      algorithm?  Should we allow the repository to specify in the role
      dictionary the algorithm used for these generated hashed paths?

    <Arguments>
      child_role:
        The delegation targets role object of 'child_role', containing its
        paths, path_hash_prefixes, keys, and so on.

      target_filepath:
        The path to the target file on the repository. This will be relative to
        the 'targets' (or equivalent) directory on a given mirror.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      If 'child_role' has been delegated the target with the name
      'target_filepath', then we return the role name of 'child_role'.

      Otherwise, we return None.
    """

    child_role_name = child_role['name']
    child_role_paths = child_role.get('paths')
    child_role_path_hash_prefixes = child_role.get('path_hash_prefixes')

    if child_role_path_hash_prefixes is not None:
        target_filepath_hash = _get_target_hash(target_filepath)
        for child_role_path_hash_prefix in child_role_path_hash_prefixes:
            if not target_filepath_hash.startswith(child_role_path_hash_prefix):
                continue

            return child_role_name

    elif child_role_paths is not None:
        # Is 'child_role_name' allowed to sign for 'target_filepath'?
        for child_role_path in child_role_paths:
            # A child role path may be an explicit path or glob pattern (Unix
            # shell-style wildcards).  The child role 'child_role_name' is
            # returned if 'target_filepath' is equal to or matches
            # 'child_role_path'. Explicit filepaths are also considered
            # matches. A repo maintainer might delegate a glob pattern with a
            # leading path separator, while the client requests a matching
            # target without a leading path separator - make sure to strip any
            # leading path separators so that a match is made.
            # Example: "foo.tgz" should match with "/*.tgz".
            if fnmatch.fnmatch(target_filepath.lstrip(os.sep),
                               child_role_path.lstrip(os.sep)):
                logger.debug('Child role ' + repr(child_role_name) +
                    ' is allowed to sign for ' + repr(target_filepath))

                return child_role_name

            logger.debug(
                'The given target path ' + repr(target_filepath) +
                ' does not match the trusted path or glob pattern: ' +
                repr(child_role_path))
            continue

    else:
        # 'role_name' should have been validated when it was downloaded.
        # The 'paths' or 'path_hash_prefixes' fields should not be missing,
        # so we raise a format error here in case they are both missing.
        raise tuf.exceptions.FormatError(repr(child_role_name) + ' '
            'has neither a "paths" nor "path_hash_prefixes".  At least'
            ' one of these attributes must be present.')

    return None


def _check_file_length(file_object, trusted_file_length):

    file_object.seek(0, 2)
    observed_length = file_object.tell()

    # Return and log a message if the length 'file_object' is equal to
    # 'trusted_file_length', otherwise raise an exception.  A hard check
    # ensures that a downloaded file strictly matches a known, or trusted,
    # file length.
    if observed_length != trusted_file_length:
        raise tuf.exceptions.DownloadLengthMismatchError(trusted_file_length,
            observed_length)


def _check_hashes(file_object, trusted_hashes):

    # Verify each trusted hash of 'trusted_hashes'.  If all are valid, simply
    # return.
    for algorithm, trusted_hash in trusted_hashes.items():
        digest_object = securesystemslib.hash.digest(algorithm)
        # Ensure we read from the beginning of the file object
        # TODO: should we store file position (before the loop) and reset
        # after we seek about?
        file_object.seek(0)
        digest_object.update(file_object.read())
        computed_hash = digest_object.hexdigest()

        # Raise an exception if any of the hashes are incorrect.
        if trusted_hash != computed_hash:
            raise securesystemslib.exceptions.BadHashError(trusted_hash,
                computed_hash)

        logger.info('The file\'s ' + algorithm + ' hash is'
            ' correct: ' + trusted_hash)



def _get_target_hash(target_filepath, hash_function='sha256'):

    # Calculate the hash of the filepath to determine which bin to find the
    # target.  The client currently assumes the repository (i.e., repository
    # tool) uses 'hash_function' to generate hashes and UTF-8.
    digest_object = securesystemslib.hash.digest(hash_function)
    encoded_target_filepath = target_filepath.encode('utf-8')
    digest_object.update(encoded_target_filepath)
    target_filepath_hash = digest_object.hexdigest()

    return target_filepath_hash

def neither_403_nor_404(mirror_error):
    if isinstance(mirror_error, tuf.exceptions.FetcherHTTPError):
        if mirror_error.status_code in {403, 404}:
            return False
    return True
