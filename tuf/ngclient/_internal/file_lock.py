# Copyright 2025, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Platform-specific support for file locking

"""

import os
import sys


if sys.platform in ['win32']:
    def create_lockfile(filename: str) -> str:
        # Use the name of the file but create lockfile in %TEMP%.
        fn = os.path.basename(filename)
        lockfile = os.path.join(os.getenv("TEMP"), "tuf" + fn)
        #try:
        #    with open(filename, "w+") as f:
        #        f.truncate(1)
        #        f.flush()
        #except:
        #    pass
        return lockfile
else:
    def create_lockfile(filename: str) -> str:
        return filename
