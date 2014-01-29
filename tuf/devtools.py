"""
<Program Name>
  tuf-devtoools.py

<Authors>
  Santiago Torres <torresariass@gmail.com>
  Zane Fisher <zanefisher@gmail.com>

  Based on the work done by Vladimir Diaz

<Started>
  January 22, 2014 

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  See 'tuf/README' for a complete guide on using 'tuf.devtools.py'.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division

#this import is the interface to the whole tuf module, since the imports are 
# made there. 
import os
import errno
import sys
import logging
import shutil
import tempfile

import tuf
import tuf.formats
import tuf.util
import tuf.keydb
import tuf.roledb
import tuf.keys
import tuf.sig
import tuf.log
import tuf.conf
import tuf.repository_tool

from tuf.repository_tool import Targets
from tuf.repository_tool import get_metadata_file_info
from tuf.repository_tool import get_metadata_filenames
from tuf.repository_tool import generate_and_write_rsa_keypair
from tuf.repository_tool import import_rsa_publickey_from_file
from tuf.repository_tool import import_rsa_privatekey_from_file
from tuf.repository_tool import generate_and_write_ed25519_keypair
from tuf.repository_tool import import_ed25519_publickey_from_file
from tuf.repository_tool import import_ed25519_privatekey_from_file
#from tuf.import _generate_and_write_metadata
from tuf.repository_tool import _remove_invalid_and_duplicate_signatures
from tuf.repository_tool import _check_role_keys
from tuf.repository_tool import _delete_obsolete_metadata
from tuf.repository_tool import generate_targets_metadata
from tuf.repository_tool import sign_metadata
from tuf.repository_tool import write_metadata_file

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.devtools')

# Recommended RSA key sizes:
# http://www.emc.com/emc-plus/rsa-labs/historical/twirl-and-rsa-key-size.htm#table1 
# According to the document above, revised May 6, 2003, RSA keys of
# size 3072 provide security through 2031 and beyond.  2048-bit keys
# are the recommended minimum and are good from the present through 2030.
DEFAULT_RSA_KEY_BITS = 3072

# The algorithm used by the repository to generate the hashes of the
# target filepaths.  The repository may optionally organize targets into
HASH_FUNCTION = 'sha256'

# The extension of TUF metadata.
METADATA_EXTENSION = '.txt'

# The metadata filename for the targets metadata information.
TARGETS_FILENAME = 'targets' + METADATA_EXTENSION

# The targets and metadata directory names.  Metadata files are written
# to the staged metadata directory instead of the "live" one.
METADATA_STAGED_DIRECTORY_NAME = 'metadata.staged'
METADATA_DIRECTORY_NAME = 'metadata'
TARGETS_DIRECTORY_NAME = 'targets' 

# The full list of supported TUF metadata extensions.
METADATA_EXTENSIONS = ['.txt', '.txt.gz']

# The recognized compression extensions. 
SUPPORTED_COMPRESSION_EXTENSIONS = ['.gz']

# Supported key types.
SUPPORTED_KEY_TYPES = ['rsa', 'ed25519']

# Expiration date delta, in seconds, of the top-level roles.  A metadata
# expiration date is set by taking the current time and adding the expiration
# seconds listed below.

# Initial 'targets.txt' expiration time of 3 months. 
TARGETS_EXPIRATION = 7889230 


class Project(object):
  """
  <Purpose>
    This class works as the abstraction of the developer's files. this module
    was created with the objective of simplifying the publishing process using
    TUF by taking care of all of the bookkeeping, signature handling and 
    metadata integrity verification.

    This class is the direct representation of a metadata file* with the 
    intention to provide the ability to modify this data in an OOP manner
    without messing with syntax and sanity-checking.

      
  <Arguments>
    project_directory:
      The root folder of the project that contains the metadata and targets
      sub-directories.

    metadata_directory:
      The metadata sub-directory contains the files of the top-level
      roles, including all roles delegated from 'targets.txt'. 

    targets_directory:
      The targets sub-directory contains all the target files that are
      downloaded by clients and are referenced in TUF Metadata.  The hashes and
      file lengths are listed in Metadata files so that they are securely
      downloaded.  Metadata files are similarly referenced in the top-level
      metadata.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    Creates top-level role objects and assigns them as attributes.

  <Returns>
    A project object that contains default Metadata objects for the top-level
    roles.
  """
 
  def __init__(self, 
      repository_directory,
      metadata_directory,
      targets_directory,
      file_prefix,
      ):
  
    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(repository_directory)
    tuf.formats.PATH_SCHEMA.check_match(metadata_directory)
    tuf.formats.PATH_SCHEMA.check_match(targets_directory)
    tuf.formats.PATH_SCHEMA.check_match(file_prefix)

    self._repository_directory = repository_directory
    self._metadata_directory = metadata_directory
    self._targets_directory = targets_directory
   
    # Set the top-level role objects.
    self.targets = Targets(self._targets_directory, 'targets')

    self.prefix = file_prefix

  #TODO: continue where we left off.
  def write(self, write_partial=False, consistent_snapshots=False):
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

      consistent_snapshots:
        A boolean indicating whether written metadata and target files should
        include a digest in the filename (i.e., root.<digest>.txt,
        targets.<digest>.txt.gz, README.<digest>.txt, where <digest> is the
        file's SHA256 digest.  Example:
        'root.1f4e35a60c8f96d439e27e858ce2869c770c1cdd54e1ef76657ceaaf01da18a3.txt'
        
    <Exceptions>
      tuf.Error, if any of the top-level roles do not have a minimum
      threshold of signatures.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """
    
    # Does 'write_partial' have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.BOOLEAN_SCHEMA.check_match(write_partial)
    tuf.formats.BOOLEAN_SCHEMA.check_match(consistent_snapshots) 
    
    # At this point the tuf.keydb and tuf.roledb stores must be fully
    # populated, otherwise write() throwns a 'tuf.Repository' exception if 
    # any of the top-level roles are missing signatures, keys, etc.

    # Write the metadata files of all the delegated roles.
    delegated_rolenames = tuf.roledb.get_delegated_rolenames('targets')
    for delegated_rolename in delegated_rolenames:
      roleinfo = tuf.roledb.get_roleinfo(delegated_rolename)
      delegated_filename = os.path.join(self._metadata_directory,
                                        delegated_rolename + METADATA_EXTENSION)

      # Ensure the parent directories of 'metadata_filepath' exist, otherwise an
      # IO exception is raised if 'metadata_filepath' is written to a
      # sub-directory.
      tuf.util.ensure_parent_dir(delegated_filename)
      
      _generate_and_write_metadata(delegated_rolename, delegated_filename,
                                   write_partial, self._targets_directory,
                                   self._metadata_directory,
                                   consistent_snapshots,prefix=self.prefix)
      
    
    # Generate the 'targets.txt' metadata file.
    targets_filename = 'targets' + METADATA_EXTENSION 
    targets_filename = os.path.join(self._metadata_directory, targets_filename)
    release_signable, targets_filename = \
      _generate_and_write_metadata('targets', targets_filename, write_partial,
                                   self._targets_directory,
                                   self._metadata_directory,
                                   consistent_snapshots,prefix=self.prefix)
    
    
    # Delete the metadata of roles no longer in 'tuf.roledb'.  Obsolete roles
    # may have been revoked.
    _delete_obsolete_metadata(self._metadata_directory,
                              release_signable['signed'], consistent_snapshots)


  
  def write_partial(self):
    """
    <Purpose>
      Write all the JSON Metadata objects to their corresponding files, but
      allow metadata files to contain an invalid threshold of signatures.  
    
    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      Creates metadata files in the repository's metadata directory.

    <Returns>
      None.
    """

    self.write(write_partial=True)
  
  
  
  def status(self):
    """
    <Purpose>
      Determine the status of the top-level roles, including those delegated.
      status() checks if each role provides sufficient public keys, signatures,
      and that a valid metadata file is generated if write() were to be called.
      Metadata files are temporary written to check that proper metadata files
      are written, where file hashes and lengths are calculated and referenced
      by the top-level roles.  status() does not do a simple check for number
      of threshold keys and signatures.

    <Arguments>
      None.

    <Exceptions>
      None.

    <Side Effects>
      Generates and writes temporary metadata files.

    <Returns>
      None.
    """
    temp_project_directory = None

    try:
      temp_project_directory = tempfile.mkdtemp()
      metadata_directory = os.path.join(temp_project_directory,
                                        METADATA_STAGED_DIRECTORY_NAME)
      os.mkdir(metadata_directory)

      #filenames = get_metadata_filenames(metadata_directory)A
      # we should do the schema check
      filenames = {}
      filenames['targets'] = os.path.join(metadata_directory,TARGETS_FILENAME)
      
      # Delegated roles.
      delegated_roles = tuf.roledb.get_delegated_rolenames('targets')
      insufficient_keys = []
      insufficient_signatures = []
      
      for delegated_role in delegated_roles:
        try: 
          _check_role_keys(delegated_role)
        except tuf.InsufficientKeysError, e:
          insufficient_keys.append(delegated_role)
          continue
        
        roleinfo = tuf.roledb.get_roleinfo(delegated_role)
        try: 
          write_delegated_metadata_file(temp_project_directory,
                                        self._targets_directory,
                                        delegated_role, roleinfo,
                                        write_partial=False)
        except tuf.Error, e:
          insufficient_signatures.append(delegated_role)
      
      if len(insufficient_keys):
        message = 'Delegated roles with insufficient keys: '+ \
          repr(insufficient_keys)
        print(message)
        return

      if len(insufficient_signatures):
        message = 'Delegated roles with insufficient signatures: '+ \
          repr(insufficient_signatures)
        print(message) 
        return

      # Targets role.
      try: 
        _check_role_keys(self.targets.rolename)
      except tuf.InsufficientKeysError, e:
        print(str(e))
        return
      
      try:
        signable =  _generate_and_write_metadata(self.targets.rolename,
                                                filenames['targets'], False,
                                                self._targets_directory,
                                                self._metadata_directory,
                                                False)
        #_print_status(self.targets.rolename, signable)
      except tuf.Error, e:
        signable = e[1]
        #_print_status(self.targets.rolename, signable)
        return

    finally:
      shutil.rmtree(temp_project_directory, ignore_errors=True)



  def get_filepaths_in_directory(self, files_directory, recursive_walk=False,
                                 followlinks=True):
    """
    <Purpose>
      Walk the given 'files_directory' and build a list of target files found.

    <Arguments>
      files_directory:
        The path to a directory of target files.

      recursive_walk:
        To recursively walk the directory, set recursive_walk=True.

      followlinks:
        To follow symbolic links, set followlinks=True.

    <Exceptions>
      tuf.FormatError, if the arguments are improperly formatted.

      tuf.Error, if 'file_directory' is not a valid directory.

      Python IO exceptions.

    <Side Effects>
      None.

    <Returns>
      A list of absolute paths to target files in the given 'files_directory'.
    """

    # Do the arguments have the correct format?
    # Ensure the arguments have the appropriate number of objects and object
    # types, and that all dict keys are properly named.
    # Raise 'tuf.FormatError' if any are improperly formatted.
    tuf.formats.PATH_SCHEMA.check_match(files_directory)
    tuf.formats.BOOLEAN_SCHEMA.check_match(recursive_walk)
    tuf.formats.BOOLEAN_SCHEMA.check_match(followlinks)

    # Ensure a valid directory is given.
    if not os.path.isdir(files_directory):
      message = repr(files_directory)+' is not a directory.'
      raise tuf.Error(message)
   
    # A list of the target filepaths found in 'file_directory'.
    targets = []

    # FIXME: We need a way to tell Python 2, but not Python 3, to return
    # filenames in Unicode; see #61 and:
    # http://docs.python.org/2/howto/unicode.html#unicode-filenames
    for dirpath, dirnames, filenames in os.walk(files_directory,
                                                followlinks=followlinks):
      for filename in filenames:
        full_target_path = os.path.join(dirpath, filename)
        targets.append(full_target_path)

      # Prune the subdirectories to walk right now if we do not wish to
      # recursively walk files_directory.
      if recursive_walk is False:
        del dirnames[:]

    return targets





def _print_status(rolename, signable):
  """
  Non-public function prints the number of (good/threshold) signatures of
  'rolename'.
  """

  status = tuf.sig.get_signature_status(signable, rolename)
  
  message = repr(rolename)+' role contains '+ \
    repr(len(status['good_sigs']))+' / '+ \
    repr(status['threshold'])+' signatures.'
  print(message)

def _generate_and_write_metadata(rolename, metadata_filename, write_partial,
                                 targets_directory, metadata_directory,
                                 consistent_snapshots, filenames=None,
                                 prefix=''):
  """
    Non-public function that can generate and write the metadata of the specified
    top-level 'rolename'.  It also increments version numbers if:
    
    1.  write_partial==True and the metadata is the first to be written.
              
    2.  write_partial=False (i.e., write()), the metadata was not loaded as
        partially written, and a write_partial is not needed.
  """

  metadata = None 
  # Retrieve the roleinfo of 'rolename' to extract the needed metadata
  # attributes, such as version number, expiration, etc.
  roleinfo = tuf.roledb.get_roleinfo(rolename) 
  #release_compressions = tuf.roledb.get_roleinfo('release')['compressions']
  metadata = generate_targets_metadata(targets_directory,
                                       roleinfo['paths'],
                                       roleinfo['version'],
                                       roleinfo['expires'],
                                       roleinfo['delegations'],
                                       consistent_snapshots) 

  # preprend the prefix to the project's filepath to avoid signature errors
  # in upstream
  for element in metadata['targets'].keys():
    metadata['targets'][prefix+element] = metadata['targets'][element]
    if prefix != '':
      del(metadata['targets'][element])

  signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                           metadata_filename)

  # Check if the version number of 'rolename' may be automatically incremented,
  # depending on whether if partial metadata is loaded or if the metadata is
  # written with write() / write_partial(). 
  # Increment the version number if this is the first partial write.
  if write_partial:
    temp_signable = sign_metadata(metadata, [], metadata_filename)
    temp_signable['signatures'].extend(roleinfo['signatures'])
    status = tuf.sig.get_signature_status(temp_signable, rolename)
    if len(status['good_sigs']) == 0:
      metadata['version'] = metadata['version'] + 1
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)
  
  # non-partial write()
  else:
    if tuf.sig.verify(signable, rolename) and not roleinfo['partial_loaded']:
      metadata['version'] = metadata['version'] + 1
      signable = sign_metadata(metadata, roleinfo['signing_keyids'],
                               metadata_filename)

  # Write the metadata to file if contains a threshold of signatures. 
  signable['signatures'].extend(roleinfo['signatures']) 
  
  #import pdb; pdb.set_trace()
  if tuf.sig.verify(signable, rolename) or write_partial:
    _remove_invalid_and_duplicate_signatures(signable)
    compressions = roleinfo['compressions']
    filename = write_metadata_file(signable, metadata_filename, compressions,
                                   consistent_snapshots)
    
    
  # 'signable' contains an invalid threshold of signatures. 
  else:
    message = 'Not enough signatures for '+repr(metadata_filename)
    raise tuf.Error(message, signable)


  # The root and timestamp files should also be written without a digest if
  # 'consistent_snaptshots' is True.  Client may request a timestamp and root
  # file without knowing its digest and file size.
  return signable, filename 


def _prompt(message, result_type=str):
  """
    Non-public function that prompts the user for input by printing 'message',
    converting the input to 'result_type', and returning the value to the
    caller.
  """

  return result_type(raw_input(message))





def _get_password(prompt='Password: ', confirm=False):
  """
    Non-public function that returns the password entered by the user.  If
    'confirm' is True, the user is asked to enter the previously entered
    password once again.  If they match, the password is returned to the caller.
  """

  while True:
    # getpass() prompts the user for a password without echoing
    # the user input.
    password = getpass.getpass(prompt, sys.stderr)
    if not confirm:
      return password
    password2 = getpass.getpass('Confirm: ', sys.stderr)
    if password == password2:
      return password
    else:
      print('Mismatch; try again.')


def create_new_project(project_directory,prefix):
  """
  <Purpose>
    Create a new project object, instantiate barebones metadata for the 
    targets, and return a blank project object.  On disk, create_new_project()
    only creates the directories needed to hold the metadata and targets files.
    The project object returned can be directly modified to meet the designer's
    criteria and then written using the method project.write().

  <Arguments>
    project_directory:
      The directory that will eventually hold the metadata and target files of
      the project.

    prefix: 
      a string determining the "upstream" filepath to sign the metadata 
      appropiately

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

  <Side Effects>
    The 'projet_directory' directory is created if it does not exist, 
    including its metadata and targets sub-directories.

  <Returns>
    A 'tuf.devtools.Repository' object.
  """

  # Does 'project_directory' have the correct format?
  # Ensure the arguments have the appropriate number of objects and object
  # types, and that all dict keys are properly named.
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(project_directory)

  # Do the same for the prefix
  tuf.formats.PATH_SCHEMA.check_match(prefix)

  # Set the repository, metadata, and targets directories.  These directories
  # are created if they do not exist.
  project_directory = os.path.abspath(project_directory)
  metadata_directory = None
  targets_directory = None
  
  # Try to create 'repository_directory' if it does not exist.
  try:
    message = 'Creating '+repr(project_directory)
    logger.info(message)
    os.makedirs(project_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  # Check for case where 'repository_directory' has already been created. 
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass 
    else:
      raise
  
  # Set the metadata and targets directories.  The metadata directory is a
  # staged one so that the "live" repository is not affected.  The
  # staged metadata changes may be moved over to "live" after all updated
  # have been completed.
  metadata_directory = \
    os.path.join(project_directory, METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = \
    os.path.join(project_directory, TARGETS_DIRECTORY_NAME) 
  
  # Try to create the metadata directory that will hold all of the metadata
  # files, such as 'root.txt' and 'release.txt'.
  try:
    message = 'Creating '+repr(metadata_directory)
    logger.info(message)
    os.mkdir(metadata_directory)
  
  # 'OSError' raised if the leaf directory already exists or cannot be created.
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
  
  # Try to create the targets directory that will hold all of the target files.
  try:
    message = 'Creating '+repr(targets_directory)
    logger.info(message)
    os.mkdir(targets_directory)
  except OSError, e:
    if e.errno == errno.EEXIST:
      pass
    else:
      raise
 
  # Create the bare bones repository object, where only the top-level roles
  # have been set and contain default values (e.g., Root roles has a threshold
  # of 1, expires 1 year into the future, etc.)
  project = Project(project_directory,
                    metadata_directory,
                    targets_directory,
                    prefix
                    )
  
  return project



def load_repository(repository_directory):
  """
  <Purpose>
    Return a repository object containing the contents of metadata files loaded
    from the repository.

  <Arguments>
    repository_directory:

  <Exceptions>
    tuf.FormatError, if 'repository_directory' or any of the metadata files
    are improperly formatted.  Also raised if, at a minimum, the Root role
    cannot be found.

  <Side Effects>
   All the metadata files found in the repository are loaded and their contents
   stored in a libtuf.Repository object.

  <Returns>
    libtuf.Repository object.
  
  BEGIN ORIGINAL
  # Does 'repository_directory' have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(repository_directory)

  # Load top-level metadata.
  repository_directory = os.path.abspath(repository_directory)
  metadata_directory = os.path.join(repository_directory,
                                    METADATA_STAGED_DIRECTORY_NAME)
  targets_directory = os.path.join(repository_directory,
                                    TARGETS_DIRECTORY_NAME)

  # The Repository() object loaded (i.e., containing all the metadata roles
  # found) and returned.
  repository = Repository(repository_directory, metadata_directory,
                          targets_directory)
  
  filenames = get_metadata_filenames(metadata_directory)

  # The Root file is always available without a consistent snapshots digest
  # attached to the filename.  Store the 'consistent_snapshots' value read the
  # loaded Root file so that other metadata files may be located.
  # 'consistent_snapshots' value. 
  consistent_snapshots = False

  # Load the metadata of the top-level roles (i.e., Root, Timestamp, Targets,
  # and Release).
  repository, consistent_snapshots = _load_top_level_metadata(repository,
                                                              filenames)
 
  # Load delegated targets metadata.
  # Walk the 'targets/' directory and generate the fileinfo of all the files
  # listed.  This information is stored in the 'meta' field of the release
  # metadata object.
  targets_objects = {}
  loaded_metadata = []
  targets_objects['targets'] = repository.targets
  targets_metadata_directory = os.path.join(metadata_directory,
                                            TARGETS_DIRECTORY_NAME)
  if os.path.exists(targets_metadata_directory) and \
                    os.path.isdir(targets_metadata_directory):
    for root, directories, files in os.walk(targets_metadata_directory):
      
      # 'files' here is a list of target file names.
      for basename in files:
        metadata_path = os.path.join(root, basename)
        metadata_name = \
          metadata_path[len(metadata_directory):].lstrip(os.path.sep)

        # Strip the digest if 'consistent_snapshots' is True.
        # Example:  'targets/unclaimed/13df98ab0.django.txt' -->
        # 'targets/unclaimed/django.txt'
        metadata_name, digest_junk = \
          _strip_consistent_snapshots_digest(metadata_name, consistent_snapshots)

        if metadata_name.endswith(METADATA_EXTENSION): 
          extension_length = len(METADATA_EXTENSION)
          metadata_name = metadata_name[:-extension_length]
        else:
          continue
        
        # Keep a store metadata previously loaded metadata to prevent
        # re-loading duplicate versions.  Duplicate versions may occur with
        # consistent_snapshots, where the same metadata may be available in
        # multiples files (the different hash is included in each filename.
        if metadata_name in loaded_metadata:
          continue

        signable = None
        try:
          signable = tuf.util.load_json_file(metadata_path)
        except (ValueError, IOError), e:
          continue
        
        metadata_object = signable['signed']
      
        roleinfo = tuf.roledb.get_roleinfo(metadata_name)
        roleinfo['signatures'].extend(signable['signatures'])
        roleinfo['version'] = metadata_object['version']
        roleinfo['expires'] = metadata_object['expires']
        roleinfo['paths'] = metadata_object['targets'].keys()
        roleinfo['delegations'] = metadata_object['delegations']

        if os.path.exists(metadata_path+'.gz'):
          roleinfo['compressions'].append('gz')
        
        _check_if_partial_loaded(metadata_name, signable, roleinfo)
        tuf.roledb.update_roleinfo(metadata_name, roleinfo)
        loaded_metadata.append(metadata_name)

        new_targets_object = Targets(targets_directory, metadata_name, roleinfo)
        targets_object = \
          targets_objects[tuf.roledb.get_parent_rolename(metadata_name)]
        targets_objects[metadata_name] = new_targets_object
        
        targets_object._delegated_roles[(os.path.basename(metadata_name))] = \
                              new_targets_object

        # Add the keys specified in the delegations field of the Targets role.
        for key_metadata in metadata_object['delegations']['keys'].values():
          key_object = tuf.keys.format_metadata_to_key(key_metadata)
          try: 
            tuf.keydb.add_key(key_object)
          except tuf.KeyAlreadyExistsError, e:
            pass
        
        for role in metadata_object['delegations']['roles']:
          rolename = role['name'] 
          roleinfo = {'name': role['name'], 'keyids': role['keyids'],
                      'threshold': role['threshold'],
                      'compressions': [''], 'signing_keyids': [],
                      'signatures': [],
                      'partial_loaded': False,
                      'delegations': {'keys': {},
                                      'roles': []}}
          tuf.roledb.add_role(rolename, roleinfo)
  
  return repository
  """ 
  raise Exception("To be implemented")


if __name__ == '__main__':
  # The interactive sessions of the documentation strings can
  # be tested by running libtuf.py as a standalone module:
  # $ python libtuf.py.
  # import doctest
  # doctest.testmod()
  print("main")
