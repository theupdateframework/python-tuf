#!/usr/bin/env python
import argparse
import os
import shutil
import sys
from logging import exception
from pathlib import Path

from requests.exceptions import ConnectionError

from tuf.ngclient import Updater

# define directory constants
HOME_DIR = Path.home()  # user home dir
DOWNLOAD_DIR = "./downloads"  # download dir
METADATA_DIR = f"{HOME_DIR}/.local/share/tuf_metadata_example"  # metadata dir
CLIENT_EXAMPLE_DIR = os.path.dirname(os.path.abspath(__file__))  # example dir


def init():
    """
    Initialize the TUF Client infrastructure

    This function initializes the creation of the download and TUF metadata
    directory.
    """

    if not os.path.isdir(DOWNLOAD_DIR):
        os.mkdir(DOWNLOAD_DIR)

    print(f"[INFO] Download directory [{DOWNLOAD_DIR}] is created.")

    if not os.path.isdir(METADATA_DIR):
        os.makedirs(METADATA_DIR)

    print(f"[INFO] Metadata folder [{METADATA_DIR}] is created.")

    if not os.path.isfile(f"{METADATA_DIR}/root.json"):
        shutil.copy(
            f"{CLIENT_EXAMPLE_DIR}/1.root.json", f"{METADATA_DIR}/root.json"
        )
        print(f"[INFO] Bootstrap initial root metadata.")


def tuf_updater():
    """
    This function implement the ``tuf.ngclient.Updater`` and returns
    the updater.
    """
    url = "http://127.0.0.1:8000"

    try:
        updater = Updater(
            repository_dir=METADATA_DIR,
            metadata_base_url=f"{url}/metadata/",
            target_base_url=f"{url}/targets/",
            target_dir=DOWNLOAD_DIR,
        )

    except FileNotFoundError:
        print("[ERROR] The Example Client not initiated. Try using '--init'.")
        sys.exit(1)

    return updater


def download(target):
    """
    Download the target file using the TUF ``nglcient`` Updater process.

    The Updater refreshes the top-level metadata, get the target information,
    verifies if the target is already cached, and in case it is not cached,
    downloads the target file.
    """

    try:
        updater = tuf_updater()

    except ConnectionError:
        print("[ERROR] Failed to connect http://127.0.0.1:8000")
        sys.exit(1)

    updater.refresh()
    print("[INFO] Top-level metadata is refreshed.")

    info = updater.get_targetinfo(target)
    print("[INFO] Target info gotten.")

    if info is None:
        print("[ERROR] Target file not found.")
        sys.exit(1)

    path = updater.find_cached_target(info)
    if path:
        print(
            f"[INFO] File is already available in {DOWNLOAD_DIR}/{info.path}."
        )
        sys.exit(0)

    path = updater.download_target(info)

    print(f"[INFO] File downloaded available in {DOWNLOAD_DIR}/{info.path}.")


if __name__ == "__main__":

    client_args = argparse.ArgumentParser(
        description="TUF Python Client Example"
    )

    # Global arguments
    client_args.add_argument(
        "--init",
        default=False,
        help="Force register a new Engine.",
        action="store_true",
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

    if command_args.get("init") is True:
        init()

    elif not sub_commands_args:
        client_args.print_help()

    if sub_commands_args == "download":
        target = command_args.get("target")
        download(target)
