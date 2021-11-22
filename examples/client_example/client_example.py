#!/usr/bin/env python
"""Python Client Example."""

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import argparse
import logging
import os
import shutil
import sys
from pathlib import Path

from tuf.exceptions import RepositoryError
from tuf.ngclient import Updater

# define directory constants
HOME_DIR = Path.home()  # user home dir
DOWNLOAD_DIR = "./downloads"  # download dir
METADATA_DIR = f"{HOME_DIR}/.local/share/tuf_metadata_example"  # metadata dir
CLIENT_EXAMPLE_DIR = os.path.dirname(os.path.abspath(__file__))  # example dir


def init():
    """
    The function that initializes the TUF client infrastructure.

    It creates the metadata directory and downloads the ``root.json``.
    """

    if not os.path.isdir(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)

    print(f"Download directory [{DOWNLOAD_DIR}] is created")

    if not os.path.isdir(METADATA_DIR):
        os.makedirs(METADATA_DIR)

    print(f"Metadata folder [{METADATA_DIR}] is created")

    if not os.path.isfile(f"{METADATA_DIR}/root.json"):
        shutil.copy(
            f"{CLIENT_EXAMPLE_DIR}/1.root.json", f"{METADATA_DIR}/root.json"
        )
        print("Bootstrap initial root metadata")


def tuf_updater():
    """
    The function that creates the TUF updater using ``tuf.ngclient``.
    """
    url = "http://127.0.0.1:8000"

    updater = Updater(
        repository_dir=METADATA_DIR,
        metadata_base_url=f"{url}/metadata/",
        target_base_url=f"{url}/targets/",
        target_dir=DOWNLOAD_DIR,
    )

    return updater


def download(target):
    """
    The function that downloads the target file using the TUF ``nglcient``
    Updater.

    The Updater refreshes the top-level metadata, get the target information,
    verifies if the target is already cached, and in case it is not cached,
    downloads the target file.
    """

    try:
        updater = tuf_updater()

    # if the metadata is not available, it will initialize the TUF client
    except FileNotFoundError:
        print("Client infrastructure not found")
        print("Initializing the Client Infrastructure")
        init()
        updater = tuf_updater()

    # handle specific TUF error (root.json corrupted in the client metadata)
    # check out ``tuf.exceptions`` for more information
    except RepositoryError as e:
        print(e)
        sys.exit(1)

    updater.refresh()

    info = updater.get_targetinfo(target)
    print(f"Target {target} information fetched")

    if info is None:
        print(f"Target {target} not found")
        sys.exit(1)

    path = updater.find_cached_target(info)
    print(f"Cached target {target} verified")
    if path:
        print(f"Target is already available in {DOWNLOAD_DIR}/{info.path}")
        sys.exit(0)

    path = updater.download_target(info)

    print(f"Target is available in {DOWNLOAD_DIR}/{info.path}")


if __name__ == "__main__":

    client_args = argparse.ArgumentParser(
        description="TUF Python Client Example"
    )

    # Global arguments
    client_args.add_argument(
        "--init",
        default=False,
        help="Initializes the Client structure",
        action="store_true",
    )

    client_args.add_argument(
        "-v",
        "--verbose",
        help="Output verbosity level (-v, -vv, ...)",
        action="count",
        default=0,
    )

    # Sub commands
    sub_commands = client_args.add_subparsers(dest="sub_commands")

    # Download
    download_parser = sub_commands.add_parser(
        "download",
        help="Download a target file",
    )

    download_parser.add_argument(
        "target",
        metavar="TARGET",
        help="Target file",
    )

    command_args = vars(client_args.parse_args())
    sub_commands_args = command_args.get("sub_commands")

    verbose = command_args.get("verbose")

    if verbose <= 1:
        loglevel = logging.ERROR
    elif verbose == 2:
        loglevel = logging.WARNING
    elif verbose == 3:
        loglevel = logging.INFO
    else:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)

    if command_args.get("init") is True:
        init()

    elif not sub_commands_args:
        client_args.print_help()

    if sub_commands_args == "download":
        target_download = command_args.get("target")
        download(target_download)
