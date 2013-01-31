#!/usr/bin/env python
# Copyright 2010 The Update Framework.  See LICENSE for licensing information.
"""
This script provides a way for developers to push a signed targets metadata
file and the referenced targets to a repository. The repository adds these
files to the repository by running the receivetools/receive.py script.

Usage:
    ./push.py COMMAND COMMAND_ARGS
    
    Known commands:
        push

Example:
    ./push.py push push.cfg targets.txt targetfile1 targetfile2

Details of 'push' command:

The developer provides the path to a configuration file that lists:
    * The path to the targets metadata file.
    * The name of the transfer module to use for transferring the
      files to the repository (e.g. 'scp').
    * Configuration information that is specific to the transfer
      module.

See the push.cfg.sample file for an example configuration file.

The transfer module needs the following functionality:
    * A way to transfer target files and the new metadata file to the
      repository.
      
The transfer module may also include the following functionality:
    * A way to determine whether the repository has rejected the push and, if
      so, the reason for the rejection.
"""

import ConfigParser
import sys

import tuf


def _read_config_file(filename):
    """Return a dictionary where the keys are section names and the values
       are dictionaries of keys/values in that section.
    """
    config = ConfigParser.RawConfigParser()
    config.read(filename)
    configdict = {}
    for section in config.sections():
        configdict[section] = {}
        for key, value in config.items(section):
            if key in ['seconds', 'minutes', 'days', 'hours']:
                value = int(value)
            elif key in ['keyids']:
                value = value.split(',')
            if key in configdict[section]:
                configdict[section][key] = []
            else:
                configdict[section][key] = value
    return configdict


def _get_transfer_module(modulename):
    __import__("transfer.%s" % modulename)
    return sys.modules["transfer.%s" % modulename]


def push(args):
    config = _read_config_file(args[0])
    targets = args[1:]
    transfermod = _get_transfer_module(config['general']['transfer_module'])

    context = transfermod.TransferContext(config['scp'])
    context.transfer(targets, config['general']['metadata_path'])
    context.finalize()


def getstatus():
    raise NotImplementedError


def usage():
    print "Known commands:"
    print "  push config_file target [target ...]"
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in ["push", "getstatus"]:
        try:
            globals()[cmd](args)
        except tuf.BadPasswordError:
            print >> sys.stderr, "Password incorrect."
    else:
        usage()


if __name__ == '__main__':
    main()
