"""Regression tests for secret-file permissions (H1).

Secret stores (auth.json, sessions.json, settings.json) and the SQLite DB were
created at the process umask (0644 / 0755), readable by any other local user.
These tests pin the lock-down:
  - atomic_write_json/atomic_write_text honor an explicit `mode`
  - the default (no mode) is unchanged
  - _harden_db_storage tightens the data dir to 0700 and *.db* to 0600

POSIX-only: file modes are a no-op on Windows (safe_chmod returns False there).
"""

import os
import stat

import pytest

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")


def _perm(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# ── atomic_io mode parameter ─────────────────────────────────────────

def test_atomic_write_json_applies_mode(tmp_path):
    from core.atomic_io import atomic_write_json
    p = tmp_path / "secret.json"
    atomic_write_json(str(p), {"k": "v"}, indent=2, mode=0o600)
    assert _perm(str(p)) == 0o600


def test_atomic_write_json_mode_is_honored_exactly(tmp_path):
    """The requested mode is applied verbatim, not hardcoded to 0600."""
    from core.atomic_io import atomic_write_json
    p = tmp_path / "g.json"
    atomic_write_json(str(p), {"k": "v"}, mode=0o640)
    assert _perm(str(p)) == 0o640


def test_atomic_write_json_mode_survives_overwrite(tmp_path):
    """Re-saving an existing (looser) file must end at the requested mode,
    since os.replace adopts the temp file's permissions."""
    from core.atomic_io import atomic_write_json
    p = tmp_path / "s.json"
    p.write_text("{}")
    os.chmod(str(p), 0o644)
    atomic_write_json(str(p), {"k": "v"}, mode=0o600)
    assert _perm(str(p)) == 0o600


def test_atomic_write_text_applies_mode(tmp_path):
    from core.atomic_io import atomic_write_text
    p = tmp_path / "secret.txt"
    atomic_write_text(str(p), "data", mode=0o600)
    assert _perm(str(p)) == 0o600


# ── DB storage hardening ─────────────────────────────────────────────

def test_harden_db_storage_locks_dir_and_db_files(tmp_path, monkeypatch):
    import core.database as db

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(str(data_dir), 0o755)
    for name in ("app.db", "app.db-wal", "scheduled_emails.db"):
        f = data_dir / name
        f.write_bytes(b"x")
        os.chmod(str(f), 0o644)

    monkeypatch.setattr(db, "DATABASE_URL", f"sqlite:///{data_dir}/app.db")
    db._harden_db_storage()

    assert _perm(str(data_dir)) == 0o700
    assert _perm(str(data_dir / "app.db")) == 0o600
    assert _perm(str(data_dir / "app.db-wal")) == 0o600
    assert _perm(str(data_dir / "scheduled_emails.db")) == 0o600


def test_harden_db_storage_noop_for_non_sqlite(tmp_path, monkeypatch):
    """A Postgres/MySQL URL must not touch the local filesystem."""
    import core.database as db
    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://user@host/db")
    db._harden_db_storage()  # must not raise
