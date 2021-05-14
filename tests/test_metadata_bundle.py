import logging
import os
import shutil
import sys
import tempfile
import unittest

from tuf.api import metadata
from tuf.client_rework.metadata_bundle import MetadataBundle

from tests import utils

logger = logging.getLogger(__name__)

class TestMetadataBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.mkdtemp(dir=os.getcwd())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temporary_directory)

    def setUp(self):
        # copy metadata to "local repo"
        shutil.copytree(
            os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata'),
            self.temporary_directory,
            dirs_exist_ok=True
        )

    def test_local_load(self):

        # test loading all local metadata succesfully
        bundle = MetadataBundle(self.temporary_directory)
        bundle.root_update_finished()
        self.assertTrue(bundle.load_local_timestamp())
        self.assertTrue(bundle.load_local_snapshot())
        self.assertTrue(bundle.load_local_targets())
        self.assertTrue(bundle.load_local_delegated_targets('role1','targets'))
        self.assertTrue(bundle.load_local_delegated_targets('role2','role1'))

        # Make sure loading metadata without its "dependencies" fails
        bundle = MetadataBundle(self.temporary_directory)

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

    def test_update(self):
        remote_dir = os.path.join(os.getcwd(), 'repository_data', 'repository', 'metadata')

        # remove all but root.json from local repo
        os.remove(os.path.join(self.temporary_directory, "timestamp.json"))
        os.remove(os.path.join(self.temporary_directory, "snapshot.json"))
        os.remove(os.path.join(self.temporary_directory, "targets.json"))
        os.remove(os.path.join(self.temporary_directory, "role1.json"))
        os.remove(os.path.join(self.temporary_directory, "role2.json"))

        # test updating metadata succesfully
        bundle = MetadataBundle(self.temporary_directory)
        bundle.root_update_finished()

        with open(os.path.join(remote_dir, "timestamp.json"), "rb") as f:
            bundle.update_timestamp(f.read())
        with open(os.path.join(remote_dir, "snapshot.json"), "rb") as f:
            bundle.update_snapshot(f.read())
        with open(os.path.join(remote_dir, "targets.json"), "rb") as f:
            bundle.update_targets(f.read())
        with open(os.path.join(remote_dir, "role1.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role1", "targets")
        with open(os.path.join(remote_dir, "role2.json"), "rb") as f:
            bundle.update_delegated_targets(f.read(), "role2", "role1")

        # test loading the metadata (that should now be locally available)
        bundle = MetadataBundle(self.temporary_directory)
        bundle.root_update_finished()
        self.assertTrue(bundle.load_local_timestamp())
        self.assertTrue(bundle.load_local_snapshot())
        self.assertTrue(bundle.load_local_targets())
        self.assertTrue(bundle.load_local_delegated_targets('role1','targets'))
        self.assertTrue(bundle.load_local_delegated_targets('role2','role1'))

        # TODO test loading one version, then updating to new versions of each metadata


if __name__ == '__main__':
  utils.configure_test_logging(sys.argv)
  unittest.main()
