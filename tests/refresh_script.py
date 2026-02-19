import sys
import time

from tuf.ngclient import Updater

print(f"Fetching metadata {sys.argv[1]} times:")
print(f"  metadata dir: {sys.argv[2]}")
print(f"  metadata url: {sys.argv[3]}")

start = time.time()

for i in range(int(sys.argv[1])):
    try:
        refresh_start = time.time()
        u = Updater(metadata_dir=sys.argv[2], metadata_base_url=sys.argv[3])
        # file3.txt is delegated so we end up exercising all metadata load paths
        u.get_targetinfo("file3.txt")
    except OSError as e:
        print(
            f"Failed on iteration {i}, "
            f"{time.time() - refresh_start} secs elapsed ({time.time() - start} total)"
        )
        raise e
