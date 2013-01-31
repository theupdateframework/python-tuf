# Copyright 2010 The Update Framework.  See LICENSE for licensing information.
"""
SCP transfer module for the developer push mechanism.

This will use scp to upload a push directory to the repository. The directory
will be named with the current timestamp in the format XXXXXXXXXX.XX. The
directory will contain a file named 'info' that provides information about
the push, the signed metadata file, and a 'targets' directory that contains
the targets specified in the metadata.

Use of this module requires the following section to be present in the push
configuration file provided to push.py:

[scp]
host = somehost
user = someuser
identity_file = optional_path_to_ssh_key
remote_dir = ~/pushes

The remote_dir should correspond to a pushroot configured in the repository's
receive.py script.

This transfer module will output to stdout the commands it runs and the output
of those commands.

Example:

$ python pushtools/push.py push push.cfg test.txt 
Running command: scp -r /tmp/tmpc8PiXo somehost:~/test/pushes/1273704893.55
info                                         100%   21     0.0KB/s   00:00    
targets.txt                                  100%  771     0.8KB/s   00:00    
test.txt                                     100%    5     0.0KB/s   00:00
"""

import os
import shutil
import subprocess
import tempfile
import time


class TransferContext(object):

    def __init__(self, config):
        self.host = config['host']
        self.user = config.get('user')
        self.identity_file = config.get('identity_file')
        self.remote_dir = config.get('remote_dir', '.')

    def transfer(self, target_paths, metadata_path):
        """
        Create a local temporary directory with an additional file used to
        communicate additional information to the repository. This directory
        will be transferred to the repository.
        """

        basecommand = ['scp']
        if self.identity_file:
            basecommand.extend(['-i', self.identity_file])

        timestamp = time.time()
        dest = ""
        if self.user:
            dest += "%s@"
        dest += "%s:%s/%s" % (self.host, self.remote_dir, timestamp)

        tempdir = tempfile.mkdtemp()
        try:
            # Make sure the temp directory is world-readable as the permissions
            # get carried over in the scp'ing.
            os.chmod(tempdir, 0755)

            # Create a file that tells the repository the name of the targets
            # metadata file. For delegation, this will be the only way the
            # the repository knows the full role name.
            fp = open(os.path.join(tempdir, 'info'), 'w')
            fp.write("metadata=%s\n" % metadata_path)
            fp.close()

            # Copy the metadata.
            basename = os.path.basename(metadata_path)
            shutil.copy(metadata_path, os.path.join(tempdir, basename))

            # Create a directory that all target files will be put in before
            # being transferred.
            targetsdir = os.path.join(tempdir, 'targets')
            os.mkdir(targetsdir)

            # This is quite inefficient for large files, but just copy all
            # targets into the correct directory structure.
            for path in target_paths:
                dirname = os.path.dirname(path)
                basename = os.path.basename(path)
                if dirname and not os.path.exists(dirname):
                    os.makedirs(dirname)
                shutil.copy(path, os.path.join(targetsdir, basename))

            # This will create the 'timestamp' directory on the remote host and
            # it will contain the info file and an empty targets directory.
            command = basecommand[:]
            command.append('-r') # recursive
            command.append(tempdir)
            command.append(dest)
            print "Running command: %s" % ' '.join(command)
            # Raises subprocess.CalledProcessError on failure.
            subprocess.check_call(command)

        finally:
            shutil.rmtree(tempdir)

    def finalize(self):
        pass
