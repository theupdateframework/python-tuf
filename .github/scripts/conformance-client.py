#!/usr/bin/env python
"""Conformance client for python-tuf, part of tuf-conformance"""

# Copyright 2024 tuf-conformance contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import argparse
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone

from tuf.ngclient import Updater, UpdaterConfig


def init(metadata_dir: str, trusted_root: str) -> None:
    """Initialize local trusted metadata"""

    # No need to actually run python-tuf code at this point
    shutil.copyfile(trusted_root, os.path.join(metadata_dir, "root.json"))
    print(f"python-tuf test client: Initialized repository in {metadata_dir}")


def refresh(
    metadata_url: str,
    metadata_dir: str,
    days_in_future: str,
    max_root_rotations: int,
) -> None:
    """Refresh local metadata from remote"""

    updater = Updater(
        metadata_dir,
        metadata_url,
        config=UpdaterConfig(max_root_rotations=int(max_root_rotations)),
    )
    if days_in_future != "0":
        day_int = int(days_in_future)
        day_in_future = datetime.now(timezone.utc) + timedelta(days=day_int)
        updater._trusted_set.reference_time = day_in_future  # noqa: SLF001
    updater.refresh()
    print(f"python-tuf test client: Refreshed metadata in {metadata_dir}")


def download_target(
    metadata_url: str,
    metadata_dir: str,
    target_name: str,
    download_dir: str,
    target_base_url: str,
) -> None:
    """Download target."""

    updater = Updater(
        metadata_dir,
        metadata_url,
        download_dir,
        target_base_url,
        config=UpdaterConfig(prefix_targets_with_hash=False),
    )
    target_info = updater.get_targetinfo(target_name)
    if not target_info:
        raise RuntimeError(f"{target_name} not found in repository")
    updater.download_target(target_info)


def main() -> int:
    """Main TUF Client Example function"""

    parser = argparse.ArgumentParser(description="TUF Client Example")
    parser.add_argument("--metadata-url", required=False)
    parser.add_argument("--metadata-dir", required=True)
    parser.add_argument("--target-name", required=False)
    parser.add_argument("--target-dir", required=False)
    parser.add_argument("--target-base-url", required=False)
    parser.add_argument("--days-in-future", required=False, default="0")
    parser.add_argument(
        "--max-root-rotations", required=False, default=32, type=int
    )

    sub_command = parser.add_subparsers(dest="sub_command")
    init_parser = sub_command.add_parser(
        "init",
        help="Initialize client with given trusted root",
    )
    init_parser.add_argument("trusted_root")

    sub_command.add_parser(
        "refresh",
        help="Refresh the client metadata",
    )

    sub_command.add_parser(
        "download",
        help="Downloads a target",
    )

    command_args = parser.parse_args()

    # initialize the TUF Client Example infrastructure
    if command_args.sub_command == "init":
        init(command_args.metadata_dir, command_args.trusted_root)
    elif command_args.sub_command == "refresh":
        refresh(
            command_args.metadata_url,
            command_args.metadata_dir,
            command_args.days_in_future,
            command_args.max_root_rotations,
        )
    elif command_args.sub_command == "download":
        download_target(
            command_args.metadata_url,
            command_args.metadata_dir,
            command_args.target_name,
            command_args.target_dir,
            command_args.target_base_url,
        )
    else:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
