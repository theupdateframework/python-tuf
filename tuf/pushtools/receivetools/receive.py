#!/usr/bin/env python

"""
<Program Name>
  receive.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  September 2012.  Based on a previous version by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  This script can be run on a repository to import new targets metadata and
  target files into the repository. This is intended to work with the
  developer 'push.py' tool. When this script finds a new directory pushed
  by a developer, it checks the metadata and target files and, if everything
  is correct, adds the files to the repository.

  Like the 'push.py' script, 'receive.py' is provided as an optional tool for
  maintainers who wish to support the remote updating of target files.  The
  target files are provided by an outside developer.  The developer generates a
  correctly signed 'targets.txt' metatada file, along with the target files
  specified in it, and uploads them to his/her developer directory on the
  repository with 'push.py'.  A repository maintainer would then run this script
  to ensure a valid targets metadata file is provided and the target files match
  to what is listed.  Lastly, the maintainer manually generates the new
  'release.txt' and 'timestamp.txt' metadata files so that clients may download
  the newly added target files.


  Details:

  The script looks in a set of pre-defined push locations that one or more
  developers may have uploaded files to using the push tool. If it finds
  a valid push, it moves the push directory to a 'processing' directory and
  also copies the pushed files to a temporary directory (these files are the
  ones used by this script).

  Once the repository has received and copied a set of target files and the
  corresponding targets metadata file, it performs the following checks:

    * The metadata file is newer than the last metadata file of that type.
    * The metadata has not expired.
    * The metadata is signed by a threshold of keys that belong to the
      appropriate role.
    * The target files described in the metadata are the same target files as
      were provided.

  Once the verification is complete, the script backs up the files to be
  replaced or obsoleted, and then adds the new files to the repository. The
  script then moves the push directory from the pushroot's 'processing'
  directory to its 'processed' directory and writes a 'received.result' file
  to the push directory.  The 'received.result' file contains either the word
  SUCCESS or FAILURE. There may also be a 'received.log' file written.  The
  client can check these files to determine whether the push was accepted and,
  if not, what the problem was.

  This script does not generate a new 'release.txt' file or 'timestamp.txt' file.
  That needs to be done after this script runs if any pushes have been received.
  In some cases, it may make sense to have this script operate on a non-live
  copy of the repository and then rsync the files after all changes have been
  made.

  This script does not handle delegated targets metadata. When the time comes to
  implement that here, care needs to be taken to ensure that a delegated targets
  metadata file can't replace a target it shouldn't. Such untrusted files would
  not trick clients, but they would prevent clients from obtaining updates. It
  may be the case that making this script general enough to handle delegated
  targets metadata may not be worth it. Such situations may be better suited to
  customization per-project because the script could then leverage knowledge
  about how the delegation is supposed to be done.

  Usage:
  
    $ python receive.py --config <config path>
  
  Options:
 
    --config <config path>

    --verbose <1-5>
  
  Example output of this script:

  $ python receive.py --verbose 1 --config ./receive.cfg
  

  [2012-09-23 21:25:35,822] [tuf.receive] [DEBUG] Looking for pushes in pushroot
  /home/user/pushes
  [2012-09-23 21:25:35,822] [tuf.receive] [INFO] Processing /home/user/pushes/
  1348449811.39
  [2012-09-23 21:25:35,822] [tuf.receive] [DEBUG] Moving push directory to
  /home/user/pushes/processing/1348449811.39
  [2012-09-23 21:25:35,828] [tuf.receive] [DEBUG] New metadata timestamp is
  2012-09-23 23:24:17.  Replacing old metadata with timestamp 2012-09-23 23:14:19
  [2012-09-23 21:25:35,829] [tuf.receive] [DEBUG] Metadata will expire at
  2013-09-23 23:24:17
  [2012-09-23 21:25:35,834] [tuf.receive] [DEBUG] {'unknown_method_sigs': [],
  'untrusted_sigs': [], 'bad_sigs': [], 'threshold': 1, 'good_sigs': 
  [u'efed647da99d1759637a80d225fc18e1d2a778812dd753f2d98b0311f19f26a1'],
  'unknown_sigs': []}
  [2012-09-23 21:25:35,834] [tuf.receive] [INFO] Number of targets specified: 3
  [2012-09-23 21:25:35,835] [tuf.receive] [DEBUG] Size of target
  /tmp/tmpQr4P_j/push/targets/helloworld.py is correct (19 bytes).
  [2012-09-23 21:25:35,835] [tuf.receive] [DEBUG] 1 hash(es) to check.
  [2012-09-23 21:25:35,835] [tuf.receive] [DEBUG] sha256 hash of target
  /tmp/tmpQr4P_j/push/targets/helloworld.py is correct (9df93f8cd91e085db74d88c
  788ed00c9b865370fd484884c8db077f979788376).
  [2012-09-23 21:25:35,835] [tuf.receive] [DEBUG] Size of target /tmp/tmpQr4P_j
  /push/targets/LICENSE is correct (12 bytes).
  [2012-09-23 21:25:35,836] [tuf.receive] [DEBUG] 1 hash(es) to check.
  [2012-09-23 21:25:35,836] [tuf.receive] [DEBUG] sha256 hash of target /tmp/tmp
  Qr4P_j/push/targets/LICENSE is correct (f9f661288421a20acf49017975e51dd09a662b
  8e6b3ca5f676d9d1feb153986c).
  [2012-09-23 21:25:35,836] [tuf.receive] [DEBUG] Size of target /tmp/tmpQr4P_j/
  push/targets/new_file.txt is correct (10 bytes).
  [2012-09-23 21:25:35,836] [tuf.receive] [DEBUG] 1 hash(es) to check.
  [2012-09-23 21:25:35,836] [tuf.receive] [DEBUG] sha256 hash of target /tmp/tmp
  Qr4P_j/push/targets/new_file.txt is correct (f1fc221623f24cc1a31d972ddba368481
  dd03b8bb124632fef78544342797215).
  [2012-09-23 21:25:35,837] [tuf.receive] [INFO] Backing up target /var/tuf/test
  -repo/targets/helloworld.py to /var/tuf/test-repo/replaced/1348449811.39aicLFk
  /targets/helloworld.py
  [2012-09-23 21:25:35,837] [tuf.receive] [INFO] Backing up target /var/tuf/test-
  repo/targets/LICENSE to /var/tuf/test-repo/replaced/1348449811.39aicLFk/target
  s/LICENSE
  [2012-09-23 21:25:35,837] [tuf.receive] [INFO] Backing up old metadata /var/tuf
  /src/tuf/test-repo/metadata/targets.txt to /var/tuf/test-repo/replaced/13484498
  11.39aicLFk/targets.txt
  [2012-09-23 21:25:35,838] [tuf.receive] [INFO] Adding target to repository: /va
  r/tuf/test-repo/targets/helloworld.py
  [2012-09-23 21:25:35,838] [tuf.receive] [INFO] Adding target to repository: /va
  r/tuf/test-repo/targets/LICENSE
  [2012-09-23 21:25:35,839] [tuf.receive] [INFO] Adding target to repository: /va
  r/tuf/test-repo/targets/new_file.txt
  [2012-09-23 21:25:35,839] [tuf.receive] [INFO] Adding new targets metadata to 
  repository: /var/tuf/test-repo/metadata/targets.txt
  [2012-09-23 21:25:35,840] [tuf.receive] [DEBUG] Moving push directory to /home
  /user/pushes/processed/1348449811.39
  [2012-09-23 21:25:35,840] [tuf.receive] [INFO] Completed processing of all pus
  hes.  Push successes = 1, failures = 0.

"""

import errno
import os
import shutil
import sys
import tempfile
import time
import logging
import optparse

import tuf
import tuf.formats
import tuf.keydb
import tuf.roledb
import tuf.sig
import tuf.hash
import tuf.util
import tuf.log
import tuf.pushtools.pushtoolslib

# See 'log.py' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.pushtools.receivetools.receive')


def receive(config_filepath):
  """
  <Purpose> 
    Locate and process the pushes found in any of the pushroots directories.
    The pushroots are specified in the 'receive.cfg' configuration file.

                              pushroot
                                 |
          ===============================================
          |             |                 |             |
      processed     processing      12345(push1)    54321(push2) 

  <Arguments>
    config_filepath:
      The receive configuration file (i.e., 'receive.cfg').

  <Exceptions>
    tuf.FormatError, if any of the arguments are incorrectly formatted.

    tuf.Error, if there was error processing the receive.

  <Side Effects>
    If a push is processed successfully, the repository specified in the
    configuration file is updated with new target files and a 'targets.txt'
    metadata file.

  <Returns>
    None.

  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.PATH_SCHEMA.check_match(config_filepath)

  # Save a reference to the 'tuf.pushtools.pushtoolslib' module
  # to avoid long lines of code.  'pushtoolslib' is needed here
  # to read the 'receive.cfg' configuration file.
  pushtoolslib = tuf.pushtools.pushtoolslib

  # Is the path to the configuration file valid?
  if not os.path.isfile(config_filepath):
    message = 'The configuration file path is invalid.'
    raise tuf.Error(message)
  config_filepath = os.path.abspath(config_filepath)

  # Retrieve the configuration settings required by 'receive'.
  # Raise ('tuf.FormatError', 'tuf.Error') if a valid configuration file
  # cannot be retrieved.
  config_dict = pushtoolslib.read_config_file(config_filepath, 'receive')
  
  # These are the locations where developers may push files using the
  # push tools. Each push will be in its own directory with the
  # developer's push root. Each developer's push must have the directories
  # 'processed' and 'processing' writable by this script.
  pushroots = config_dict['general']['pushroots']

  # This is the directory where the repository resides. As far as this
  # script is concerned, this is the live repository. Changes will be made
  # to this repository directory.
  repository_directory = config_dict['general']['repository_directory']
  repository_directory = os.path.expanduser(repository_directory)

  # This is the metadata directory within the repository.
  # The successfully processed 'targets.txt' metadata file is saved here.
  metadata_directory = config_dict['general']['metadata_directory']
  metadata_directory = os.path.expanduser(metadata_directory)

  # This is the targets directory within the repository.
  # The successfully processed target files are saved here.
  targets_directory = config_dict['general']['targets_directory']
  targets_directory = os.path.expanduser(targets_directory)

  # Where replaced files will be stored. This will be used globally rather
  # than a separate backup/replaced files directory for each pushroot.
  backup_directory = config_dict['general']['backup_directory']
  backup_directory = os.path.expanduser(backup_directory)
  
  # Check that the various defined directories exist.
  # We don't check the 'pushroots' here because we consider it non-fatal
  # if those are missing. A log message is issued if any of those are
  # missing.
  directories_to_check = {'repository': repository_directory,
                          'metadata': metadata_directory,
                          'targets': targets_directory,
                          'backup': backup_directory}
  
  for directory_name, path in directories_to_check.items():
    if not os.path.exists(path):
      message = directory_name+' directory does not exist: '+repr(path)
      logger.error(message)
      raise tuf.Error(message)
  
  # Keep track of the number of pushes that were successfully processed,
  # or that failed.  These values are used to log/print detailed results
  # after a pushroot is processed.
  success_count = 0
  failure_count = 0

  # Process all the pushes for each of the pushroots.
  for pushroot in pushroots:
    if not os.path.exists(pushroot):
      logger.error('The pushroot '+repr(pushroot)+' does not exist. Skipping.')
      continue
   
    # Add the 'processed' and 'processing' directories if not present.
    # These directories must exist so that we can properly process
    # a push.
    logger.debug('Looking for pushes in pushroot '+repr(pushroot))
    if not os.path.exists(os.path.join(pushroot, 'processed')):
      os.mkdir(os.path.join(pushroot, 'processed'))
    if not os.path.exists(os.path.join(pushroot, 'processing')):
      os.mkdir(os.path.join(pushroot, 'processing'))
   
    # Locate all the pushed directories and process them.  'pushname'
    # should be a directory with a timestamp as its directory name.
    # TODO: Use only the newest push and move the others to the 'processed'
    # directory, adding an appropriate log file.
    for pushname in os.listdir(pushroot):
      # Skip over the 'processed' and 'processing' directories. 
      if pushname == 'processed' or pushname == 'processing':
        continue
     
      # Found a directory we can potentially process.
      pushpath = os.path.join(pushroot, pushname)
      if os.path.isdir(pushpath):
        # Ensure the 'info' file exists.  A successful push operation creates
        # and saves this 'info' file to the push directory.
        if not os.path.exists(os.path.join(pushpath, 'info')):
          message = 'Skipping incomplete push '+repr(pushpath)+' (no info file).'
          logger.warn(message)
          continue
        
        # Process the new push and record if it was processed successfully.
        # Raise 'tuf.Error' if a push processing error cannot be logged
        # to a file properly. 
        success = _process_new_push(pushroot, pushname, metadata_directory,
                                    targets_directory, backup_directory)
        if success:
          success_count += 1
        else:
          failure_count += 1
   
    # Done.  Log the result of processing the pushes for 'pushroot'.
    message = 'Completed processing of all pushes.  Push successes = '+\
               repr(success_count)+', failures = '+repr(failure_count)+'.'
    logger.info(message)





def _process_new_push(pushroot, pushname, metadata_directory,
                      targets_directory, backup_directory):
  """
  <Purpose>
    Process a push.
    
    This will check the validity of targets metadata in the push (including
    whether the signatures are trusted) and, if valid, will copy the targets
    metadata and target files to the repository.
  
  <Arguments>
    pushroot:
      The root directory containing the developer's pushes.  This root is one
      of multiple directories listed under the 'pushroots' entry in the
      'receive.cfg' configuration file.
    
    pushname:
      The name of the directory (i.e., '1348449811.39') containing the pushed
      files.

    metadata_directory:
      The directory where the repository's metadata files (e.g., 'targets.txt',
      'root.txt') are stored.

    targets_directory:
      The directory where the repository's target files are stored.

    backup_directory:
      The directory where the pushed directories are saved after a 
      successful 'receive'.
  
  <Exceptions>
    tuf.Error, if a push processing error cannot be written to
    'receive.result'.

  <Side Effects>
    Directories are created, the repository updated, and log files
    added.

  <Returns>
    Boolean.  True on success, False on failure.
  
  """
    
  logger.info('Processing '+repr(pushroot)+'/'+repr(pushname))

  # Move the pushed directory to the 'processing' directory.
  pushpath = os.path.join(pushroot, 'processing', pushname)
  logger.debug('Moving push directory to '+repr(pushpath))
  if os.path.isdir(pushpath) or os.path.isfile(pushpath):
    os.remove(pushpath)
  os.rename(os.path.join(pushroot, pushname), pushpath)

  # Process 'pushpath' and log the appropriate results.
  try:
    try:
      # Raise 'tuf.Error' if the copied push cannot be properly processed.
      _process_copied_push(pushpath, metadata_directory,
                           targets_directory, backup_directory)
      # Write the '{pushpath}/receive.result' file that indicates SUCCESS.
      # The developer may later read this file to quickly determine if
      # the push was successfully processed.
      try:
        file_object = open(os.path.join(pushpath, 'receive.result'), 'w')
      except IOError, e:
        raise tuf.Error('Unable to open "receive.result" file: '+str(e))
      try:
        file_object.write('SUCCESS')
        file_object.write('\n')
      finally:
        file_object.close()
      return True
    
    except tuf.Error, e:
      # Write the '{pushpath}/receive.result' file that indicates FAILURE.
      try:
        file_object = open(os.path.join(pushpath, 'receive.result'), 'w')
      except IOError, e:
        raise tuf.Error('Unable to open "receive.result" file: '+str(e))
      try:
        file_object.write("FAILURE")
        file_object.write('\n')
      finally:
        file_object.close()
      
      # Log the error message to {pushpath}/receive.log
      # The developer may later search this log file for specific
      # error messages on failed push attempts.
      try:
        file_object = open(os.path.join(pushpath, 'receive.log'), 'a')
      except IOError, e:
        raise tuf.Error('Unable to open receive log file: '+str(e))
      try:
        file_object.write(str(e))
        file_object.write('\n')
      finally:
        file_object.close()
      
      message = 'Could not process: '+repr(pushroot)+'/'+repr(pushname)
      logger.exception(message)
      return False
  
  # On success or failure, move 'pushpath' to the processed directory.
  finally:
    processedpath = os.path.join(pushroot, 'processed', pushname)
    logger.debug('Moving push directory to '+repr(processedpath))
    if os.path.isdir(processedpath) or os.path.isfile(processedpath):
      os.remove(processedpath)
    os.rename(pushpath, processedpath)





def _process_copied_push(pushpath, metadata_directory,
                         targets_directory, backup_directory):
  """
  <Purpose>
    Helper function for _process_new_push().
    
    This does the actual work of copying pushpath to a temp directory,
    checking the metadata and targets, and copying the files to the
    repository on success. The push is valid and successfully processed
    if no exception is raised.
  
  <Arguments>
    pushpath:
      The push directory currently being processed (i.e., the 'processing'
      directory on the developer's pushroot)
    
    metadata_directory:
      The directory where the repository's metadata files (e.g., 'targets.txt',
      'root.txt') are stored.

    targets_directory:
      The directory where the repository's target files are stored.

    backup_directory:
      The directory where the pushed directories are saved after a 
      successful 'receive'.

  <Exceptions>
    tuf.Error, if there is an error processing the push.
  
  <Side Effects>
    The repository is updated if the push is successful.

  <Returns>
    None.

  """
  
  # The push's timestamp directory name (e.g., '1348449811.39')
  pushname = os.path.basename(pushpath)

  # Copy the contents of pushpath to a temp directory. We don't want the
  # user modifying the files we work with.  The temp directory is only
  # accessible by the calling process.
  temporary_directory = tempfile.mkdtemp()
  push_temporary_directory = os.path.join(temporary_directory, 'push')
  shutil.copytree(pushpath, push_temporary_directory)
  
  # Read the 'root' metadata of the current repository.  'root.txt'
  # is needed to authorize the 'targets' metadata file.
  root_metadatapath = os.path.join(metadata_directory, 'root.txt')
  root_signable = tuf.util.load_json_file(root_metadatapath)
  
  # Ensure 'root_signable' is properly formatted.
  try:
    tuf.formats.check_signable_object_format(root_signable)
  except tuf.FormatError, e:
    raise tuf.Error('The repository contains an invalid "root.txt".')
 
  # Extract the metadata object and load the key and role databases.
  # The keys and roles are needed to verify the signatures of the
  # metadata files.
  root_metadata = root_signable['signed']
  tuf.keydb.create_keydb_from_root_metadata(root_metadata)
  tuf.roledb.create_roledb_from_root_metadata(root_metadata)

  # Determine the name of the targets metadata file that was pushed.
  # The required 'info' file should list the metadata file that was
  # pushed by the developer.  Only 'targets.txt' currently supported
  # (i.e., no delegated roles are accepted).
  new_targets_metadata_file = None
  try:
    file_object = open(os.path.join(push_temporary_directory, 'info'), 'r')
  except IOError, e:
    raise tuf.Error('Unable to open push "info" file: '+str(e))
  try:
    # Inspect each line of the 'info' file, searching for the line that
    # specifies the targets metadata file.  Raise an exception if all
    # the lines are processed without finding the 'metadata=' line.
    for line in file_object:
      # Search 'info' for a 'metadata=.../targets.txt' line.
      parts = line.strip().split('=')
      if parts[0] == 'metadata':
        metadata_basename = os.path.basename(parts[1])
        if metadata_basename != 'targets.txt':
          message = 'No support yet for pushing delegated targets metadata.'
          raise tuf.Error(message)
        else:
          new_targets_metadata_file = parts[1]
          break
    else:
      raise tuf.Error('No "metadata=" line in push info file.')
  finally:
    file_object.close()

  # Read the new targets metadata that was pushed.
  new_targets_metadatapath = os.path.join(push_temporary_directory,
                                      new_targets_metadata_file)
  new_targets_signable = tuf.util.load_json_file(new_targets_metadatapath)

  # Ensure 'new_targets_signable' is properly formatted.
  try:
    tuf.formats.check_signable_object_format(new_targets_signable)
  except tuf.FormatError, e:
    raise tuf.Error('The pushed targets metadata file is invalid.')
  
  # Read the existing targets metadata from the repository.
  targets_metadatapath = os.path.join(metadata_directory, 'targets.txt')

  # Check the metadata. This is mostly to make sure we don't replace good
  # metadata with bad metadata as clients do their own security checking.
  # This is what we check:
  #   * it is newer than the last metadata.
  #   * it has not expired.
  #   * all signatures valid.
  #   * a threshold of trusted signatures. only check the delegating
  #     role rather than the trust hierachy all the way up.
  #   * all of the files listed in the metadata were provided and have
  #     the sizes and hashes listed in the metadata.

  # Check that the new metadata file is newer than the existing metadata.
  if os.path.exists(targets_metadatapath):
    targets_signable = tuf.util.load_json_file(targets_metadatapath)

    # Ensure 'targets_signable' is properly formatted.
    try:
      tuf.formats.check_signable_object_format(targets_signable)
    except tuf.FormatError, e:
      raise tuf.Error('The repository\'s targets metadata file is invalid.')
   
    # Extract the timestamp value of the current targets metadata.
    # This value is used to determine if the new metadata is newer.
    timestamp = targets_signable['signed']['ts']
    formatted_timestamp = tuf.formats.parse_time(timestamp)

    # Extract the timestamp of the new targets metadata.
    new_timestamp = new_targets_signable['signed']['ts']
    new_formatted_timestamp = tuf.formats.parse_time(new_timestamp)

    # Allowing equality makes testing/development easier.
    if formatted_timestamp > new_formatted_timestamp:
      message = 'Existing metadata timestamp '+repr(timestamp)+' is newer '+\
      'than the new metadata\'s timestamp '+repr(new_timestamp)
      raise tuf.Error(message)
    else:
      message = 'New metadata timestamp is '+repr(new_timestamp)+'. '+\
        ' Replacing old metadata with timestamp '+repr(timestamp)
      logger.debug(message)

  # There appears to be no 'targets.txt' metadata file on the repository.
  else:
    message = 'The old targets metadata file '+repr(targets_metadatapath)+'. '+\
      'doesn\'t exist in the repo. Skipping the timestamp check.'
    logger.warn(message)

  # Ensure the new metadata is not expired.
  expiration = new_targets_signable['signed']['expires']
  formatted_expiration = tuf.formats.parse_time(expiration)
  
  if formatted_expiration <= time.time():
    message = 'Pushed metadata expired at '+repr(expiration)
    raise tuf.Error(message)
  else:
    message = 'Metadata will expire at '+repr(expiration)
    logger.debug(message)

  # Verify the signatures of the new targets metadata.
  if not tuf.sig.verify(new_targets_signable, 'targets'):
    message = 'The pushed targets metadata file does not '+\
      'have the required number of good signatures.'
    raise tuf.Error(message)
  # Log the status of the signatures.  For example, the number of good,
  # bad, untrusted, unknown, signatures. 
  status = tuf.sig.get_signature_status(new_targets_signable, 'targets')
  logger.debug(repr(status))

  # Log the number of targets specified in the new targets metadata file.
  targets_count = len(new_targets_signable['signed']['targets'].keys())
  message = 'Number of targets specified: '+repr(targets_count)
  logger.info(message)

  # Verify the files of the new targets metadata file.
  new_targets_dict = new_targets_signable['signed']['targets']
  for target_relativepath, target_info in new_targets_dict.items():
    targets_basename = os.path.basename(targets_directory)
    targetpath = os.path.join(push_temporary_directory, targets_basename,
                               target_relativepath)
    
    # Check that the target was provided.
    if not os.path.exists(targetpath):
      message = 'The specified target file was not provided: '+\
        repr(target_relativepath)
      raise tuf.Error(message)

    # Check the target's size.  A valid size is required of target files.
    target_size = os.path.getsize(targetpath)
    if target_size != target_info['length']:
      message = 'The size of target file '+repr(target_relativepath)+\
        ' is incorrect: was '+repr(target_size)+', expected '+\
        repr(target_info['length'])
      raise tuf.Error(message)
    else:
      message = 'Size of target '+repr(targetpath)+' is correct '+\
        '('+repr(target_size)+' bytes).'
      logger.debug(message)

    # Check hashes.  Valid target files is required.
    hash_count = len(target_info['hashes'].items())
    if hash_count == 0:
      message = repr(targetpath)+' contains an empty hashes dictionary.'
      raise tuf.Error(message)
    else:
      logger.debug(repr(hash_count)+' hash(es) to check.')
    
    for algorithm, digest in target_info['hashes'].items():
      digest_object = tuf.hash.digest_filename(targetpath, algorithm=algorithm)
      if digest_object.hexdigest() != digest:
        message = repr(algorithm)+' hash does not match: '+\
          ' was '+repr(digest_object.hexdigest())+', expected '+\
          repr(digest)
        raise tuf.Error(message)
      else:
        message = repr(algorithm)+' hash of target '+repr(targetpath)+\
          ' is correct ('+repr(digest)+').'
        logger.debug(message)

  # At this point, the targets metadata and all specified files have been
  # verified.  Remove the files referenced by the old targets metadata as
  # well as the old targets metadata itself.
  # Raise 'tuf.Error' if there is an error backing up the old targets.
  _remove_old_files(targets_metadatapath, pushname,
                    targets_directory, backup_directory)

  # Copy the new target files into place on the repository.
  for target_relativepath in new_targets_signable['signed']['targets'].keys():
    targets_basename = os.path.basename(targets_directory)
    source_path = os.path.join(push_temporary_directory, targets_basename,
                               target_relativepath)
    destination_path = os.path.join(targets_directory, target_relativepath)
    logger.info('Adding target to repository: '+repr(destination_path))
    destination_directory = os.path.dirname(destination_path)
    if not os.path.exists(destination_directory):
      os.mkdir(destination_directory)
    shutil.copy(source_path, destination_path)

  # Copy the new targets metadata file into place on the repository.
  message = 'Adding new targets metadata to repository: '+repr(targets_metadatapath)
  logger.info(message)
  shutil.copy(new_targets_metadatapath, targets_metadatapath)





def _remove_old_files(targets_metadatapath, pushname,
                      targets_directory, backup_directory):
  """
  <Purpose>
    Remove metadata and target files that will be replaced.
    
    This does not take into account any targets that are the same between
    the old and new metadata. For simplicity, all old targets are removed
    and thus even targets that remained the same will need to be copied
    into place after this has been called.
    
    This function currently assumes that the the metadata file is the
    top-level 'targets.txt' file rather than a delegated metadata file
    and that the arguments have been validated (i.e., exist, correct, etc).
    
  <Arguments>
    targets_metadatapath:
      The old targets metadata file to be replaced, along with all of
      its referenced targets.

    pushname:
      The name of the directory (i.e., timestamp name) containing the pushed
      files.
    
    targets_directory:
      The directory where the repository's target files are stored.

    backup_directory:
      The directory where the pushed directories are saved to after a 
      successful 'receive'.

  <Exceptions>
    tuf.Error, if there is an error backing up the old targets. 

  <Side Effects>
    Replaces the old 'targets.txt' metadata file and removes all of the old
    target files.

  <Returns>
    None.

  """
    
  # Create the backup destination directories.  The old target files
  # and target metadata are backed up to these directories.
  backup_destdirectory = os.path.join(backup_directory, pushname)
  os.mkdir(backup_destdirectory)
  targets_basename = os.path.basename(targets_directory)
  backup_targetsdirectory = os.path.join(backup_destdirectory, targets_basename)
  os.mkdir(backup_targetsdirectory)

  # Load the old 'targets.txt' file and determine all the targets to be replaced.
  # Need to ensure we only remove target files specified by 'targets.txt'.
  targets_signable = tuf.util.load_json_file(targets_metadatapath)
  for target_relativepath in targets_signable['signed']['targets'].keys():
    targetpath = os.path.join(targets_directory, target_relativepath)
    backup_targetpath = os.path.join(backup_targetsdirectory, target_relativepath)
    message = 'Backing up target '+repr(targetpath)+' to '+repr(backup_targetpath)
    logger.info(message)
   
    # Move the old target file to the backup directory.  Create any
    # directories along the way.
    if os.path.exists(targetpath):
      try:
        os.makedirs(os.path.dirname(backup_targetpath))
      except OSError, e:
        if e.errno == errno.EEXIST:
          pass
        else:
          raise tuf.Error(str(e))
      os.rename(targetpath, backup_targetpath)
    else:
      message = 'The old target '+repr(targetpath)+' doesn\'t exist in the repo.'
      logger.warn(message)

  # Backup the old 'targets.txt' metadata file.
  backup_targets_metadatafile = os.path.join(backup_destdirectory, 'targets.txt')
  message = 'Backing up old metadata '+repr(targets_metadatapath)+\
    ' to '+repr(backup_targets_metadatafile)
  logger.info(message)
  if os.path.isfile(backup_targets_metadatafile):
    os.remove(backup_targets_metadatafile)
  os.rename(targets_metadatapath, backup_targets_metadatafile)





def parse_options():
  """
  <Purpose>
    Parse the command-line options.  'receive.py' expects the '--config'
    option to be set by the user.

    Example:
      $ python receive.py --config ./receive.cfg

    The '--config' option accepts a path argument to the receive configuration
    file (i.e., 'receive.cfg').  If the required option is unset, a parser error
    is printed and the script exits.

    The '--verbose' option sets the verbosity level of the TUF logger.  Accepts
    values 1-5.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    Sets the logging level of the TUF logger.

  <Returns>
    The options object returned by the parser's parse_args() method.

  """

  usage = 'usage: %prog --config <config path>'
  option_parser = optparse.OptionParser(usage=usage)

  # Add the options supported by 'receive' to the option parser.
  option_parser.add_option('--config', action='store', type='string',
                           help='Specify the "receive.cfg" configuration file.')

  option_parser.add_option('--verbose', dest='VERBOSE', type=int, default=2,
                           help='Set the verbosity level (1-5) of logging '
                           'messages.  The lower the setting, the greater the '
                           'verbosity.')
  
  (options, remaining_arguments) = option_parser.parse_args()

  # Ensure the '--config' option is set.  If the required option is unset,
  # option_parser.error() will print an error message and exit.
  if options.config is None:
    message = '"--config" must be set on the command-line.'
    option_parser.error(message)

  # Set the logging level.
  if options.VERBOSE == 5:
    tuf.log.set_log_level(logging.CRITICAL)
  elif options.VERBOSE == 4:
    tuf.log.set_log_level(logging.ERROR)
  elif options.VERBOSE == 3:
    tuf.log.set_log_level(logging.WARNING)
  elif options.VERBOSE == 2:
    tuf.log.set_log_level(logging.INFO)
  elif options.VERBOSE == 1:
    tuf.log.set_log_level(logging.DEBUG)
  else:
    tuf.log.set_log_level(logging.NOTSET)

  return options





if __name__ == '__main__':
  options = parse_options()

  # Perform a 'receive' of the pushroots specified in the configuration file.
  try:
    receive(options.config)
  except (tuf.FormatError, tuf.Error), e:
    sys.stderr.write('Error: '+str(e)+'\n')
    sys.exit(1)

  # The 'receive' and command-line options were processed successfully.
  sys.exit(0)
