# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client public API."""

from tuf.api.metadata import TargetFile
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.updater import Updater
from tuf.ngclient.urllib3_fetcher import Urllib3Fetcher

__all__ = [  # noqa: PLE0604
    FetcherInterface.__name__,
    Urllib3Fetcher.__name__,
    TargetFile.__name__,
    Updater.__name__,
    UpdaterConfig.__name__,
]
