"""Unit tests for 'tests/generated_data/generate_md.py'."""

# Copyright New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

import sys
import unittest

from tests import utils
from tests.generated_data.generate_md import generate_all_files


class TestMetadataGeneration(unittest.TestCase):
    """Test metadata files generation."""

    @staticmethod
    def test_compare_static_md_to_generated() -> None:
        # md_generator = MetadataGenerator("generated_data/ed25519_metadata")
        generate_all_files(dump=False, verify=True)


# Run unit test.
if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
