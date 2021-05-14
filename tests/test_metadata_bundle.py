import logging
import os
import sys
import unittest

from tuf.api import metadata
from tuf.client_rework.metadata_bundle import MetadataBundle

from tests import utils

logger = logging.getLogger(__name__)

class TestMetadataBundle(unittest.TestCase):
    def test_local_load(self):
        repo_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')

        # test loading all local metadata succesfully
        bundle = MetadataBundle(repo_dir)
        bundle.root_update_finished()
        self.assertTrue(bundle.load_local_timestamp())
        self.assertTrue(bundle.load_local_snapshot())
        self.assertTrue(bundle.load_local_targets())
        self.assertTrue(bundle.load_local_delegated_targets('role1','targets'))
        self.assertTrue(bundle.load_local_delegated_targets('role2','role1'))

        # Make sure loading metadata without its "dependencies" fails
        bundle = MetadataBundle(repo_dir)

        with self.assertRaises(RuntimeError):
            bundle.load_local_timestamp()
        bundle.root_update_finished()
        with self.assertRaises(RuntimeError):
            bundle.load_local_snapshot()
        self.assertTrue(bundle.load_local_timestamp())
        with self.assertRaises(RuntimeError):
            bundle.load_local_targets()
        self.assertTrue(bundle.load_local_snapshot())
        with self.assertRaises(RuntimeError):
            bundle.load_local_delegated_targets('role1','targets')
        self.assertTrue(bundle.load_local_targets())
        with self.assertRaises(RuntimeError):
            bundle.load_local_delegated_targets('role2','role1')
        self.assertTrue(bundle.load_local_delegated_targets('role1','targets'))
        self.assertTrue(bundle.load_local_delegated_targets('role2','role1'))


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
