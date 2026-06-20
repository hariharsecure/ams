from __future__ import annotations

import fcntl
import os
from pathlib import Path


def full_fsync(fd: int) -> None:
    request = getattr(fcntl, "F_FULLFSYNC", None)
    if request is None:
        return
    try:
        fcntl.fcntl(fd, request)
    except OSError:
        return


def fsync_dir(path: Path) -> None:
    flags = getattr(os, "O_DIRECTORY", 0) | os.O_RDONLY
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(fd)
        full_fsync(fd)
    finally:
        os.close(fd)


def fsync_path(path: Path) -> None:
    with path.open("rb") as fh:
        os.fsync(fh.fileno())
        full_fsync(fh.fileno())
