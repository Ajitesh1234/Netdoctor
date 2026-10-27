"""Filesystem helpers."""

from __future__ import annotations

import contextlib
import os
import secrets

DEFAULT_REPORT_MODE = 0o600  # owner-only: reports contain internal hostnames, addresses and findings


def open_private(path: str, flags: int, mode: int = DEFAULT_REPORT_MODE) -> int:
    """``os.open`` with an explicit creation mode (the kernel still applies the umask)."""
    return os.open(path, flags | getattr(os, "O_BINARY", 0), mode)


def atomic_write_text(path: str, text: str, mode: int = DEFAULT_REPORT_MODE) -> None:
    """Write ``text`` to ``path`` so readers never observe a half-written file.

    The data goes to a uniquely named temporary file in the same directory, is flushed to disk, and is
    moved into place with :func:`os.replace` (atomic on POSIX and Windows).

    **Permissions are least-privilege by default**: the file is created ``0o600`` (owner only) because a
    report lists internal hostnames, addresses and findings. Pass a wider ``mode`` (for example ``0o644`` so
    the Prometheus textfile collector, which runs as another user, can read it) deliberately. The mode is given
    to ``os.open`` together with ``O_CREAT | O_EXCL`` so the kernel applies it, minus the umask, atomically:
    no ``chmod`` afterwards and no temporary change of the process-wide umask (which would race with other
    threads creating files).
    """
    directory = os.path.dirname(os.path.abspath(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    for _ in range(16):
        tmp = os.path.join(directory, f".netdoctor-{secrets.token_hex(8)}.tmp")
        try:
            fd = open_private(tmp, flags, mode)
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
