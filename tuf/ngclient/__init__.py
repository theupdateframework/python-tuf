# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF client public API."""

from tuf.api.metadata import TargetFile

# requests_fetcher is public but comes from _internal for now (because
# sigstore-python 1.0 still uses the module from there). requests_fetcher
# can be moved out of _internal once sigstore-python 1.0 is not relevant.
from tuf.ngclient._internal.requests_fetcher import RequestsFetcher
from tuf.ngclient.config import UpdaterConfig
from tuf.ngclient.fetcher import FetcherInterface
from tuf.ngclient.updater import Updater

__all__ = [  # noqa: PLE0604
    FetcherInterface.__name__,
    RequestsFetcher.__name__,
    TargetFile.__name__,
    Updater.__name__,
    UpdaterConfig.__name__,
]
