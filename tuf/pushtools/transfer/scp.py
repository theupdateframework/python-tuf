"""
<Program Name>
  scp.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  August 2012.  Based on a previous version of this module by Geremy Condra.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  SCP (secure copy) transfer module for the developer push mechanism.

  This will use scp to upload a push directory to the repository. The directory
  will be named with the current timestamp in the format XXXXXXXXXX.XX. The
  directory will contain a file named 'info' that provides information about
  the push, the signed metadata file, and a 'targets' directory that contains
  the targets specified in the metadata.

  Use of this module requires the following section to be present in the push
  configuration file provided to 'push.py':

  [scp]
  host = host
  user = user
  identity_file = optional_path_to_ssh_key
  remote_directory = ~/pushes

  The 'remote_directory' should correspond to a pushroot configured in the
  repository's 'receive.py' configuration file.

  This transfer module will output to stdout the commands it runs and the output
  of those commands.

  Example:

  $ python pushtools/push.py --config ./push.cfg 
  
  Running command: scp -r /tmp/tmpXi0GZH user@host:~/pushes/1348352878.31
  
  helloworld.py                                  100%   13     0.0KB/s   00:00    
  LICENSE                                        100%   12     0.0KB/s   00:00    
  targets.txt                                    100%    7     0.0KB/s   00:00    
  info                                           100%   32     0.0KB/s   00:00    

"""

import os
import shutil
import subprocess
import tempfile
import time

import tuf
import tuf.formats


def transfer(scp_config_dict):
  """
  <Purpose>
    Create a local temporary directory with an added 'info' file used to
    communicate additional information to the repository. This directory
    will be transferred to the repository.
    
  <Arguments>
    scp_config_dict:
      The dict containing the options to use with the SCP command.

  <Exceptions>
    tuf.FormatError, if the arguments are improperly formatted.

    tuf.Error, if the transfer failed. 

  <Side Effects>
    Files specified in 'push.cfg' will be transfered to a host using
    'scp'.
  
  <Returns>
    None.
  
  """

  # Do the arguments have the correct format?
  # Raise 'tuf.FormatError' if there is a mismatch.
  tuf.formats.SCPCONFIG_SCHEMA.check_match(scp_config_dict)
 
  # Extract the required 'scp' entries.  If an entry contains
  # a path argument, Tilde Expansions or user home symbols
  # are converted.
  host = scp_config_dict['scp']['host']
  user = scp_config_dict['scp']['user']
 
  # The SCP command accepts an optional path to an SSH private key file.
  identity_file = scp_config_dict['scp']['identity_file']
  identity_file = os.path.expanduser(identity_file)
 
  # The directory on the host the target files will be pushed to.
  remote_directory = scp_config_dict['scp'].get('remote_directory', '.')
  remote_directory = os.path.expanduser(remote_directory)
 
  # The 'targets.txt' metadata file to be pushed to the host. 
  metadata_path = scp_config_dict['general']['metadata_path']
  metadata_path = os.path.expanduser(metadata_path)
 
  # The local targets directory containing the target to be pushed.
  targets_directory = scp_config_dict['general']['targets_directory']
  targets_directory = os.path.expanduser(targets_directory)
  
  basecommand = ['scp']
  if identity_file:
    basecommand.extend(['-i', identity_file])

  # Build the destination.
  # Example: 'user@localhost:~/pushes/1273704893.55'
  timestamp = time.time()
  destination = ''
  if user:
    destination = destination+user+'@'
  destination = destination+host+':'+remote_directory+'/'+str(timestamp)

  temporary_directory = tempfile.mkdtemp()
  try:
    # Make sure the temp directory is world-readable, as the permissions
    # get carried over in the scp'ing.
    os.chmod(temporary_directory, 0755)

    # Create a file that tells the repository the name of the targets
    # metadata file. For delegation, this will be the only way the
    # the repository knows the full role name.
    file_object = open(os.path.join(temporary_directory, 'info'), 'w')
    file_object.write('metadata='+metadata_path+'\n')
    file_object.close()

    # Copy the targets metadata.
    basename = os.path.basename(metadata_path)
    shutil.copy(metadata_path, os.path.join(temporary_directory, basename))

    # Create a directory that all target files will be put in before
    # being transferred.
    temporary_targets_directory = os.path.join(temporary_directory, 'targets')

    # Copy all the targets into the correct directory structure.
    shutil.copytree(targets_directory, temporary_targets_directory)

    # This will create the 'timestamp' directory on the remote host.  The
    # 'timestamp' directory will contain the 'info' file, targets metadata,
    # and the targets directory being pushed.
    command = basecommand[:]
    # Add the recursive option, which will add the full contents of
    # 'temporary_directory'
    command.append('-r')
    command.append(temporary_directory)
    command.append(destination)
    # Example 'command':
    # ['scp', '-i', '/home/user/.ssh/id_dsa', '-r', '/tmp/tmpmxWxLS',
    #  'user@host:~/pushes/1348349228.4']
    print 'Running command: '+' '.join(command)
    
    # 'subprocess.CalledProcessError' raised on scp command failure.
    # Catch the exception and raise 'tuf.Error'.
    # For important security information on 'subprocess',
    # See http://docs.python.org/library/subprocess.html
    try: 
      subprocess.check_call(command)
    except subprocess.CalledProcessError, e:
      message = 'scp.transfer failed.'
      raise tuf.Error(message)
  finally:
    shutil.rmtree(temporary_directory)
