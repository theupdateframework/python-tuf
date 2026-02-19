import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import IO

logger = logging.getLogger(__name__)

try:
    # advisory file locking for posix
    import fcntl

    @contextmanager
    def lock_file(path: str) -> Iterator[IO]:
        with open(path, "wb") as f:
            fcntl.lockf(f, fcntl.LOCK_EX)
            yield f

except ModuleNotFoundError:
    # Windows file locking, in belt-and-suspenders-from-Temu style:
    # Use a loop that tries to open the lockfile for 30 secs, but also
    # use msvcrt.locking().
    # * since open() usually just fails when another process has the file open
    #   msvcrt.locking() almost never gets called when there is a lock. open()
    #   sometimes succeeds for multiple processes though
    # * msvcrt.locking() does not even block until file is available: it just
    #   tries once per second in a non-blocking manner for 10 seconds. So if
    #   another process keeps opening the file it's unlikely that we actually
    #   get the lock
    import msvcrt

    @contextmanager
    def lock_file(path: str) -> Iterator[IO]:
        err = None
        locked = False
        for _ in range(100):
            try:
                with open(path, "wb") as f:
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                    locked = True
                    yield f
                    return
            except FileNotFoundError:
                # could be from yield or from open() -- either way we bail
                raise
            except OSError as e:
                if locked:
                    # yield has raised, let's not continue loop
                    raise e
                err = e
                logger.warning("Unsuccessful lock attempt for %s: %s", path, e)
                time.sleep(0.3)

        # raise the last failure if we never got a lock
        if err is not None:
            raise err
