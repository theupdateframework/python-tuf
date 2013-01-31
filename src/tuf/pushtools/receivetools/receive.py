#!/usr/bin/env python
# Copyright 2010 The Update Framework.  See LICENSE for licensing information.
"""
This script can be run on a repository to import new targets metadata and
target files into the repository. This is intended to work with the
developer push tools. When this script finds a new directory pushed
by a developer, it checks the metadata and target files and, if everything
is good, adds the files to the repository.

Usage:
    ./receive.py

Arguments:
    None

Details:

The script looks in a set of pre-defined push locations that one or more
developers may have uploaded files to using the push tools. If it finds
a valid push, it moves the push directory to a 'processing' directory and
also copies the pushed files to a temporary directory (these files are the
ones used by this script).

Once the repository has received and copied a set of target files and the
corresponding targets metadata file, it performs the following checks that:

    * The metadata file is newer than the last metadata file of that type.
    * The metadata has not expired.
    * The metadata is signed by a threshold of keys that belong to the
      appropriate role.
    * The target files described in the metadata are the same target files as
      were provided.

Once the verification is completed, the script backs up the files to be replaced
or obsoleted and then adds the new files to the repository. The script then
moves the push directory from the pushroot's 'processing' directory to its
'processed' directory and write a 'received.result' file to the push directory
that contains either the word SUCCESS or FAILURE. There may also be a
received.log file written, as well. The client can check these files to determine
whether the push was accepted and, if not, what the problem was.

This script does not generate a new release.txt file or timestamp.txt file.
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

Example output of this script:

$ python receivetools/receive.py 
[2010-05-12 15:54:55,683] [tuf] [DEBUG] Looking for pushes in pushroot /tmp/tuf/test/pushes
[2010-05-12 15:54:55,684] [tuf] [INFO] Processing /tmp/tuf/test/pushes/1273704893.55
[2010-05-12 15:54:55,684] [tuf] [DEBUG] Moving push directory to
    /tmp/tuf/test/pushes/processing/1273704893.55
[2010-05-12 15:54:55,693] [tuf] [DEBUG] Metadata timestamp is 2010-05-06 00:13:46
    (replacing metdata with timestamp 2010-05-06 00:13:46)
[2010-05-12 15:54:55,693] [tuf] [DEBUG] Metadata will expire at 2011-05-06 00:13:46
[2010-05-12 15:54:55,693] [tuf] [DEBUG] Signatures: threshold: 1 / good:
    [u'50792c6713637cf09e1aeb3805fc6d18f80d0a4f4ab7895f4a7cdf1abd7f5b0a'] / bad [] /
    unrecognized: [] / unauthorized: [] / unknown method: []
[2010-05-12 15:54:55,693] [tuf] [INFO] Number of targets specified: 1
[2010-05-12 15:54:55,694] [tuf] [DEBUG] Size of target
    /tmp/tuf/test/pushes/processing/1273704893.55/targets/test.txt is correct (5 bytes).
[2010-05-12 15:54:55,694] [tuf] [DEBUG] 1 hashes to check.
[2010-05-12 15:54:55,694] [tuf] [DEBUG] sha256 hash of target
    /tmp/tuf/test/pushes/processing/1273704893.55/targets/test.txt is correct
    (f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2).
[2010-05-12 15:54:55,694] [tuf] [INFO] Backing up target
    /var/tuf/repo/targets/test.txt to /var/tuf/replaced/1273704893.55Tsr9QJ/targets/test.txt
[2010-05-12 15:54:55,695] [tuf] [INFO] Backing up old metadata
    /var/tuf/repo/meta/targets.txt to /var/tuf/replaced/1273704893.55Tsr9QJ/targets.txt
[2010-05-12 15:54:55,695] [tuf] [INFO] Adding target to repo: /var/tuf/repo/targets/test.txt
[2010-05-12 15:54:55,695] [tuf] [INFO] Adding new targets metadata to repo:
    /var/tuf/repo/meta/targets.txt
[2010-05-12 15:54:55,696] [tuf] [DEBUG] Moving push directory to
    /tmp/tuf/test/pushes/processed/1273704893.55
[2010-05-12 15:54:55,696] [tuf] [INFO] Completed processing of all push roots.
    Push successes = 1, failures = 0.

"""

import errno
import os
import shutil
import sys
import tempfile
import time

import tuf.formats
import tuf.hash
import tuf.keydb
import tuf.log
import tuf.sig

logger = tuf.log.get_logger()


# These are the locations where developers may push files to using the
# push tools. Each push will be in its own directory with the
# developer's push root. Each developer's push either must have the
# directories 'processed' and 'processing' which are writable by this
# script.
PUSHROOTS = ['/home/SOMEUSER/pushes']

# This is the directory where the repository resides. As far as this
# script is concerned, this is the live repository. Changes will be made
# directory to this repository.
REPODIR = '/var/tuf/repo'

# This is the metadata directory within the repository.
METADIR = os.path.join(REPODIR, 'meta')

# This is the targets directory within the repository.
TARGETSDIR = os.path.join(REPODIR, 'targets')

# Where replaced files will be stored. This will be used globally rather
# than a separate backup/replaced files directory for each pushroot.
BACKUPDIR = '/var/tuf/replaced'


def run():
    """Look for and process pushes found in any PUSHROOTS."""
    successcount = 0
    failurecount = 0
    for pushroot in PUSHROOTS:
        if not os.path.exists(pushroot):
            logger.error("The pushroot %s does not exist. Skipping." % pushroot)
            continue
        logger.debug('Looking for pushes in pushroot %s' % pushroot)
        if not os.path.exists(os.path.join(pushroot, 'processed')):
            os.mkdir(os.path.join(pushroot), 'processed')
        if not os.path.exists(os.path.join(pushroot, 'processing')):
            os.mkdir(os.path.join(pushroot), 'processing')
        # TODO: use only the newest push and move the others to the 'processed'
        #       directory, adding an appropriate log file.
        for name in os.listdir(pushroot):
            pushpath = os.path.join(pushroot, name)
            if name == 'processed' or name == 'processing':
                continue
            if os.path.isdir(pushpath):
                if not os.path.exists(os.path.join(pushpath, 'info')):
                    logger.warn("Skipping incomplete push %s (no info file)."
                                % pushpath)
                    continue
                success = process_new_push(pushroot, name)
                if success:
                    successcount += 1
                else:
                    failurecount += 1
        logger.info("Completed processing of all push roots. "
                    "Push successes = %s, failures = %s." %
                    (successcount, failurecount))


def process_old_push(pushroot, pushname):
    """When there are multiple pushes, only the newest is used. All of the
       older ones are ignored. This function makes the appropriate logs for
       an old push and moves it into the 'processed' directory."""
    raise NotImplementedError


def append_to_receive_log(pushpath, msg):
    """Appends msg to [pushpath]/receive.log"""
    try:
        fp = open(os.path.join(pushpath, 'receive.log'), 'a')
    except IOError, e:
        raise tuf.Error('Unable to open receive log file: %s' % e)
    try:
        fp.write(msg)
        fp.write('\n')
    finally:
        fp.close()


def record_receive_result(pushpath, success):
    """Writes the [pushpath]/receive.result file that indicates SUCCESS or
       FAILURE."""
    try:
        fp = open(os.path.join(pushpath, 'receive.result'), 'w')
    except IOError, e:
        raise tuf.Error('Unable to open receive result file: %s' % e)
    try:
        if success:
            fp.write("SUCCESS")
        else:
            fp.write("FAILURE")
        fp.write('\n')
    finally:
        fp.close()


def process_new_push(pushroot, pushname):
    """Process a push.
    
    This will check the validity of targets metadata in the push (including
    whether the signatures are trusted) and, if valid, will copy the targets
    metadata and target files to the repository.

    Args:
        pushroot:
        pushname:
    """
    logger.info("Processing %s/%s" % (pushroot, pushname))

    pushpath = os.path.join(pushroot, 'processing', pushname)
    logger.debug("Moving push directory to %s" % pushpath)
    os.rename(os.path.join(pushroot, pushname), pushpath)

    # Copy the contents of pushpath to a temp directory. We don't want the
    # user to be able to modify the files we work with.
    tempdir = tempfile.mkdtemp()
    pushtempdir = os.path.join(tempdir, 'push')
    shutil.copytree(pushpath, pushtempdir)

    try:
        try:
            _process_copied_push(pushpath)
            record_receive_result(pushpath, True)
            return True
        except (tuf.Error, OSError), e:
            record_receive_result(pushpath, False)
            append_to_receive_log(pushpath, str(e))
            logger.exception("Processing failed for push: %s/%s" %
                             (pushroot, pushname))
            return False
    finally:
        processedpath = os.path.join(pushroot, 'processed', pushname)
        logger.debug("Moving push directory to %s" % processedpath)
        os.rename(pushpath, processedpath)


def _process_copied_push(pushpath):
    """Helper function for process_new_push.
    
    This does the actual work of copying pushpath to a temp directory,
    checking the metadata and targets, and copying the files to the
    repository on success. The push is valid and successfully processed
    if no exception is raised.
    
    Raises:
        OSError or tuf.Error.
    """
    pushname = os.path.basename(pushpath)

    # Read the metadata of the current repository.
    rootmetapath = os.path.join(METADIR, 'root.txt')
    root_json = tuf.util.load_json_file(rootmetapath)
    root_meta = root_json['signed']
    root_obj = tuf.formats.RootFile.from_meta(root_meta)
    keydb = tuf.keydb.KeyDB.create_from_root(root_obj)

    # Determine the name of the targets metadata file that was pushed.
    targetsmetafile = None
    try:
        fp = open(os.path.join(pushpath, 'info'), 'r')
    except IOError, e:
        raise tuf.Error('Unable to open push info file: %s' % e)
    try:
        for line in fp:
            parts = line.strip().split('=')
            if parts[0] == 'metadata':
                if parts[1] != 'targets.txt':
                    raise NotImplementedError('No support yet for pushing ' +
                                              'delegated targets metadata.')
                else:
                    targetsmetafile = parts[1]
                    break
        else:
            raise tuf.Error('No metadata= line in push info file.')
    finally:
        fp.close()

    # Read the new metadata that was pushed.
    targetsmetapath = os.path.join(pushpath, targetsmetafile)
    targets_json = tuf.util.load_json_file(targetsmetapath)

    # Read the existing metadata from the repository.
    repotargetsmetapath = os.path.join(METADIR, targetsmetafile)

    # Check the metadata. This is mostly to make sure we don't replace good
    # metadata with bad metadata as clients do their own security checking.
    # This is what we check:
    #    * it is newer than the last metadata.
    #    * it has not expired.
    #    * all signatures valid.
    #    * a threshold of trusted signatures. only check the delegating
    #        role rather than the trust hierachy all the way up.
    #    * all of the files listed in the metadata were provided and have
    #        the sizes and hashes listed in the metadata.

    # Check that the new metadata is newer than the existing metadata.
    if os.path.exists(repotargetsmetapath):
        repo_targets_json = tuf.util.load_json_file(targetsmetapath)
        cur_timestamp_string = repo_targets_json['signed']['ts']
        cur_meta_timestamp = tuf.formats.parse_time(cur_timestamp_string)

        new_timestamp_string = targets_json['signed']['ts']
        new_meta_timestamp = tuf.formats.parse_time(new_timestamp_string)

        # Allowing equality makes testing/development easier.
        if cur_meta_timestamp > new_meta_timestamp:
            raise tuf.Error("Existing metadata timestamp (%s) is newer than "
                            "the new metadata's timestamp (%s)" %
                            (cur_timestamp_string, new_timestamp_string))
        else:
            logger.debug('Metadata timestamp is %s (replacing metdata with '
                         'timestamp %s)' %
                         (new_timestamp_string, cur_timestamp_string))

    else:
        logger.warn("The old targets metadata file %s doesn't exist in "
                    "the repo. Skipping timestamp check." %
                    repotargetsmetapath)

    # Ensure the metadata is not expired.
    expiration_string = repo_targets_json['signed']['expires']
    expiration_timestamp = tuf.formats.parse_time(expiration_string)
    if expiration_timestamp <= time.time():
        raise tuf.Error("Pushed metadata expired at %s" % expiration_string)
    else:
        logger.debug('Metadata will expire at %s' % expiration_string)

    # This raises tuf.BadSignature if the check fails.
    status = tuf.sig.check_signatures(targets_json, keydb, role='targets')
    logger.debug('Signatures: %s' % status)

    logger.info("Number of targets specified: %s" %
                len(targets_json['signed']['targets'].keys()))

    for targetrelpath, targetinfo in targets_json['signed']['targets'].items():
        targetpath = os.path.join(pushpath, 'targets', targetrelpath)

        # Check that the target was provided.
        if not os.path.exists(targetpath):
            raise tuf.Error('The specified target file was not provided: %s',
                            targetrelpath)

        # Check size.
        actualsize = os.path.getsize(targetpath)
        if actualsize != targetinfo['length']:
            raise tuf.Error('The size of target file %s is incorrect: ' +
                            'was %s, expected %s' % (targetrelpath, actualsize,
                                                     targetinfo['length']))
        else:
            logger.debug('Size of target %s is correct (%s bytes).' %
                         (targetpath, actualsize))

        # Check hashes.
        hashcount = len(targetinfo['hashes'].items())
        if hashcount == 0:
            raise tuf.Error('Empty hashes dictionary.')
        else:
            logger.debug('%s hashes to check.' % hashcount)
        for hashalg, hashval in targetinfo['hashes'].items():
            d_obj = tuf.hash.Digest(hashalg)
            d_obj.update_filename(targetpath)
            if d_obj.format() != hashval:
                raise tuf.Error('%s hash does not match: was %s, expected %s' %
                                (hashalg, d_obj.format(), hashval))
            else:
                logger.debug('%s hash of target %s is correct (%s).' %
                             (hashalg, targetpath, hashval))

    # At this point, the targets metadata and all specified files have been
    # verified. 

    # Remove the files referenced by the old targets metadata as well as the
    # old targets metadata itself.
    _remove_old_files(repotargetsmetapath, pushname)

    # Copy the new target files into place on the repository. 
    for targetrelpath in targets_json['signed']['targets'].keys():
        srcpath = os.path.join(pushpath, 'targets', targetrelpath)
        destpath = os.path.join(TARGETSDIR, targetrelpath)
        logger.info("Adding target to repo: %s" % destpath)
        destdir = os.path.dirname(destpath)
        if not os.path.exists(destdir):
            os.mkdir(destdir)
        shutil.copy(srcpath, destpath)

    # Copy the targets metadata into place on the repository.
    logger.info("Adding new targets metadata to repo: %s" %
                repotargetsmetapath)
    shutil.copy(targetsmetapath, repotargetsmetapath)


def _remove_old_files(oldtargetsfile, pushname):
    """Remove metadata and target files that will be replaced.
    
    This does not take into account any targets that are the same between
    the old and new metadata. For simplicity, all old targets are removed
    and thus even targets that remained the same will need to be copied
    into place after this has been called.
    
    This function currently assumes that the the metadata file is the
    top-level targets.txt file rather than a delegated metadata file.
    
    Args:
        oldtargetsfile: The old targets metadata file that is to be
            replaced, along with all of its referenced targets.
    """
    if not os.path.exists(oldtargetsfile):
        logger.warn("The old targets metadata file %s doesn't exist in "
                    "the repo. Skipping file backup." % oldtargetsfile)
        return

    backupdestdir = tempfile.mktemp(prefix=pushname, dir=BACKUPDIR)
    os.mkdir(backupdestdir)
    backuptargetsdir = os.path.join(backupdestdir, 'targets')
    os.mkdir(backuptargetsdir)

    targets_json = tuf.util.load_json_file(oldtargetsfile)
    for targetrelpath in targets_json['signed']['targets'].keys():
        curtargetpath = os.path.join(TARGETSDIR, targetrelpath)
        baktargetpath = os.path.join(backuptargetsdir, targetrelpath)
        logger.info("Backing up target %s to %s" % (curtargetpath, baktargetpath))
        if os.path.exists(curtargetpath):
            mkdir_p(os.path.dirname(baktargetpath))
            os.rename(curtargetpath, baktargetpath)
        else:
            logger.warn("The old target %s doesn't exist in the repo." %
                        curtargetpath)

    baktargetsmetafile = os.path.join(backupdestdir, 'targets.txt')
    logger.info("Backing up old metadata %s to %s" % (oldtargetsfile,
                                                      baktargetsmetafile))
    os.rename(oldtargetsfile, baktargetsmetafile)


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError, err:
        if err.errno == errno.EEXIST:
            pass
        else: raise


def _check_directories_exist():
    """Check that the various defined directories exist."""
    # We don't check the PUSHROOTS here because we consider it non-fatal
    # if those are missing. A log message is issued if any of those are
    # missing.
    dirs_to_check = {'REPODIR':REPODIR, 'METADIR':METADIR,
                     'TARGETSDIR':TARGETSDIR, 'BACKUPDIR':BACKUPDIR}
    for name, path in dirs_to_check.items():
        if not os.path.exists(path):
            logger.error("%s directory does not exist: %s" % (name, path))
            sys.exit(1)


if __name__ == "__main__":
    _check_directories_exist()
    run()
