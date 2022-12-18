# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TUF
"""

import tuf.api
import tuf.ngclient

# This value is used in the requests user agent.
__version__ = "2.0.0"
__all__ = [
    tuf.api.__name__,
    tuf.ngclient.__name__,
]
