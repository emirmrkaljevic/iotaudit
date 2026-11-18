"""Country database path resolution and download helper. No live downloads."""

from __future__ import annotations

import gzip
from datetime import date
from pathlib import Path

import pytest

from iotaudit.cli import main
from iotaudit.geoip import (
    month_urls,
    resolved_mmdb,
    source_kind,
    update_mmdb,
    user_mmdb_path,
    validate_mmdb,
)


def test_month_urls_try_current_then_previous():
    assert month_urls(date(2026, 11, 18)) == [
        ("2026-11", "https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz"),
        ("2026-10", "https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz"),
    ]
    assert month_urls(date(2026, 1, 5))[1][0] == "2025-12"


def test_resolved_mmdb_order(tmp_path, monkeypatch):
    bundled = tmp_path / "bundled.mmdb"
    user = tmp_path / "user" / "dbip-country-lite.mmdb"
    custom = tmp_path / "custom.mmdb"
    bundled.write_bytes(b"bundled")
    monkeypatch.setattr("iotaudit.geoip.bundled_mmdb", lambda: bundled)
    monkeypatch.setattr("iotaudit.geoip.user_mmdb_path", lambda: user)
    monkeypatch.delenv("IOTAUDIT_GEOIP", raising=False)

    assert resolved_mmdb(None) == bundled

    user.parent.mkdir()
    user.write_bytes(b"user")
    assert resolved_mmdb(None) == user
    assert source_kind(user) == "downloaded"

    monkeypatch.setenv("IOTAUDIT_GEOIP", str(custom))
    custom.write_bytes(b"env")
    assert resolved_mmdb(None) == custom
    assert source_kind(custom) == "custom"

    explicit = tmp_path / "explicit.mmdb"
    explicit.write_bytes(b"flag")
    assert resolved_mmdb(str(explicit)) == explicit


def test_update_falls_back_to_previous_month(tmp_path):
    dest = tmp_path / "dbip-country-lite.mmdb"
    seen: list[str] = []

    def fetch(url: str) -> bytes:
        seen.append(url)
        if "2026-11" in url:
            import urllib.error

            raise urllib.error.HTTPError(url, 404, "Not Found", hdrs=None, fp=None)
        return gzip.compress(b"mmdb-bytes")

    path, stamp = update_mmdb(
        dest,
        today=date(2026, 11, 18),
        fetch=fetch,
        validate=lambda _path: None,
    )
    assert path == dest
    assert stamp == "2026-10"
    assert dest.read_bytes() == b"mmdb-bytes"
    assert any("2026-11" in url for url in seen)
    assert any("2026-10" in url for url in seen)


def test_update_rejects_bad_gzip_and_keeps_the_old_file(tmp_path):
    dest = tmp_path / "dbip-country-lite.mmdb"
    dest.write_bytes(b"keep-me")

    def fetch(_url: str) -> bytes:
        return b"this-is-not-gzip"

    with pytest.raises(ValueError, match="gzip"):
        update_mmdb(dest, today=date(2026, 11, 18), fetch=fetch, validate=lambda _path: None)
    assert dest.read_bytes() == b"keep-me"


def test_update_rejects_an_invalid_database(tmp_path):
    dest = tmp_path / "dbip-country-lite.mmdb"

    def fetch(_url: str) -> bytes:
        return gzip.compress(b"not-an-mmdb")

    def validate(_path: Path) -> None:
        raise ValueError("not a usable country database")

    with pytest.raises(ValueError, match="usable"):
        update_mmdb(dest, today=date(2026, 11, 18), fetch=fetch, validate=validate)
    assert not dest.exists()


def test_validate_mmdb_accepts_the_bundled_file():
    from iotaudit.geoip import bundled_mmdb

    path = bundled_mmdb()
    assert path is not None
    validate_mmdb(path)


def test_geoip_status_and_update_cli(tmp_path, capsys, monkeypatch):
    dest = tmp_path / "dbip-country-lite.mmdb"
    monkeypatch.setattr("iotaudit.geoip.user_mmdb_path", lambda: dest)
    monkeypatch.delenv("IOTAUDIT_GEOIP", raising=False)

    def fake_update(dest_arg, **_kwargs):
        path = Path(dest_arg)
        path.write_bytes(b"x")
        return path, "2026-11"

    monkeypatch.setattr("iotaudit.geoip.update_mmdb", fake_update)
    assert main(["geoip", "update", "--out", str(dest)]) == 0
    out = capsys.readouterr().out
    assert "2026-11" in out and str(dest.resolve()) in out
    assert chr(0x2014) not in out and chr(0x2013) not in out

    monkeypatch.setattr("iotaudit.geoip.bundled_mmdb", lambda: None)
    assert main(["geoip"]) == 0
    status = capsys.readouterr().out
    assert str(dest) in status and "downloaded" in status


def test_user_mmdb_path_is_under_home():
    path = user_mmdb_path()
    assert path.name == "dbip-country-lite.mmdb"
    assert path.parent.name == "iotaudit"
