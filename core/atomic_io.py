"""Atomic JSON file writes.

Use this everywhere a JSON config file is persisted. A plain `open("w") +
json.dump` truncates the file on first write and only fills it with new
content afterwards — a kill -9 / power loss / OOM in between produces a
truncated or empty file. For password DBs (`auth.json`) and live state
(`sessions.json`, `settings.json`, `integrations.json`, `cookbook_state.json`),
that's a data-loss event.

`atomic_write_json` writes to a sibling tmp file, fsyncs, then `os.replace`s
into place. On POSIX `os.replace` is atomic on the same filesystem.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

from core.platform_compat import safe_chmod


def atomic_write_json(
    path: str, data: Any, *, indent: Optional[int] = None, mode: Optional[int] = None
) -> None:
    """Atomically persist `data` as JSON at `path`.

    The temp file uses the live PID as a suffix so two processes saving the
    same file (e.g. unit tests) don't collide on the rename target.

    `mode` (e.g. ``0o600``) is applied to the temp file *before* the rename, so
    the final file never exists with looser default-umask permissions even for
    an instant. Used for secret stores (auth.json, sessions.json, settings.json)
    so they aren't world-readable — see H1. No-op on Windows.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent)
        f.flush()
        os.fsync(f.fileno())
    if mode is not None:
        safe_chmod(tmp, mode)
    os.replace(tmp, path)


def atomic_write_text(path: str, text: str, *, mode: Optional[int] = None) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    if mode is not None:
        safe_chmod(tmp, mode)
    os.replace(tmp, path)
