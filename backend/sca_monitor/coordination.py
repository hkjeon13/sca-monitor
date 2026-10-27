"""Let interactive requests finish between individual background import records."""

from contextlib import contextmanager
from pathlib import Path
import fcntl
import time


class InteractiveBusyError(TimeoutError):
    pass


@contextmanager
def interactive_write(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "interactive-write.lock").open("a") as handle:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise InteractiveBusyError(
                        "interactive write queue is busy"
                    ) from None
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def yield_to_interactive(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True)
    with (data_dir / "interactive-write.lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_SH)
        fcntl.flock(handle, fcntl.LOCK_UN)
