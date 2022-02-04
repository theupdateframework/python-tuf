#!/usr/bin/env python
"""TUF Client Example"""

# Copyright 2012 - 2017, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import argparse
import logging
import os
import shutil
from pathlib import Path

from tuf.api.exceptions import DownloadError, RepositoryError
from tuf.ngclient import Updater

# constants
BASE_URL = "http://127.0.0.1:8000"
DOWNLOAD_DIR = "./downloads"
METADATA_DIR = f"{Path.home()}/.local/share/python-tuf-client-example"
CLIENT_EXAMPLE_DIR = os.path.dirname(os.path.abspath(__file__))


def init() -> None:
    """Initialize local trusted metadata and create a directory for downloads"""

    if not os.path.isdir(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)

    if not os.path.isdir(METADATA_DIR):
        os.makedirs(METADATA_DIR)

    if not os.path.isfile(f"{METADATA_DIR}/root.json"):
        shutil.copy(
            f"{CLIENT_EXAMPLE_DIR}/1.root.json", f"{METADATA_DIR}/root.json"
        )
        print(f"Added trusted root in {METADATA_DIR}")

    else:
        print(f"Found trusted root in {METADATA_DIR}")


def download(target: str) -> bool:
    """
    Download the target file using ``ngclient`` Updater.

    The Updater refreshes the top-level metadata, get the target information,
    verifies if the target is already cached, and in case it is not cached,
    downloads the target file.

    Returns:
        A boolean indicating if process was successful
    """
    try:
        updater = Updater(
            metadata_dir=METADATA_DIR,
            metadata_base_url=f"{BASE_URL}/metadata/",
            target_base_url=f"{BASE_URL}/targets/",
            target_dir=DOWNLOAD_DIR,
        )
        updater.refresh()

        info = updater.get_targetinfo(target)

        if info is None:
            print(f"Target {target} not found")
            return True

        path = updater.find_cached_target(info)
        if path:
            print(f"Target is available in {path}")
            return True

        path = updater.download_target(info)
        print(f"Target downloaded and available in {path}")

    except (OSError, RepositoryError, DownloadError) as e:
        print(f"Failed to download target {target}: {e}")
        return False

    return True


def main() -> None:
    """Main TUF Client Example function"""

    client_args = argparse.ArgumentParser(description="TUF Client Example")

    # Global arguments
    client_args.add_argument(
        "-v",
        "--verbose",
        help="Output verbosity level (-v, -vv, ...)",
        action="count",
        default=0,
    )

    # Sub commands
    sub_command = client_args.add_subparsers(dest="sub_command")

    # Download
    download_parser = sub_command.add_parser(
        "download",
        help="Download a target file",
    )

    download_parser.add_argument(
        "target",
        metavar="TARGET",
        help="Target file",
    )

    command_args = client_args.parse_args()

    if command_args.verbose == 0:
        loglevel = logging.ERROR
    elif command_args.verbose == 1:
        loglevel = logging.WARNING
    elif command_args.verbose == 2:
        loglevel = logging.INFO
    else:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)

    # initialize the TUF Client Example infrastructure
    init()

    if command_args.sub_command == "download":
        download(command_args.target)

    else:
        client_args.print_help()


if __name__ == "__main__":
    main()
