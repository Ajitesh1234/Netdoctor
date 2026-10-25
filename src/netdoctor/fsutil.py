"""Filesystem helpers."""

from __future__ import annotations

import contextlib
import os
import tempfile


def atomic_write_text(path: str, text: str) -> None:
    """Write ``text`` to ``path`` so readers never observe a half-written file.

    The data is written to a temporary file in the same directory, flushed to disk, and moved into
    place with :func:`os.replace` (atomic on POSIX and Windows). On POSIX the file is made readable
    per the process umask (``0o666 & ~umask``) so collectors running as another user can read it.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".netdoctor-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if os.name == "posix":
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp, 0o666 & ~umask)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
