"""Filesystem helpers."""

from __future__ import annotations

import contextlib
import os
import secrets


def atomic_write_text(path: str, text: str) -> None:
    """Write ``text`` to ``path`` so readers never observe a half-written file.

    The data goes to a uniquely named temporary file in the same directory, is flushed to disk, and is
    moved into place with :func:`os.replace` (atomic on POSIX and Windows).

    The temporary file is created with ``O_CREAT | O_EXCL`` and mode ``0o666``: the kernel applies the
    process umask atomically, so the result has the permissions an ordinary new file would (for example
    ``0o644`` under the common umask ``022``), which lets collectors running as another user read it. There is
    deliberately no ``chmod`` and no temporary change of the process-wide umask (that would race with
    other threads creating files).
    """
    directory = os.path.dirname(os.path.abspath(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    for _ in range(16):
        tmp = os.path.join(directory, f".netdoctor-{secrets.token_hex(8)}.tmp")
        try:
            fd = os.open(tmp, flags, 0o666)
            break
        except FileExistsError:
            continue
    else:  # pragma: no cover - 16 collisions of a 64-bit random name
        raise FileExistsError("could not create a unique temporary file")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
