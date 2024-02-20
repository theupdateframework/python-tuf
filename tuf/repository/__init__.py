# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Repository API: A helper library for repository implementations

This module is intended to make any "metadata editing" applications easier to
implement: this includes repository applications, CI integration components as
well as developer and signing tools.

The repository module is not considered part of the stable python-tuf API yet.
"""

from tuf.repository._repository import AbortEdit, Repository  # noqa: F401
