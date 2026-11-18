"""Locate or refresh the DB-IP Lite country database used for report countries."""

from __future__ import annotations

import gzip
import io
import os
import tempfile
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

DB_NAME = "dbip-country-lite.mmdb"
DOWNLOAD_UA = "iotaudit (https://github.com/emirmrkaljevic/iotaudit)"
DOWNLOAD_TIMEOUT = 60


def user_mmdb_path() -> Path:
    """Default place for a downloaded copy, next to dated auto reports."""
    return Path.home() / "iotaudit" / DB_NAME


def bundled_mmdb() -> Path | None:
    try:
        from importlib import resources

        path = resources.files("iotaudit") / "data" / DB_NAME
        return Path(str(path)) if path.is_file() else None
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError, OSError):
        return None


def resolved_mmdb(explicit: str | None = None) -> Path | None:
    """Pick a country database.

    Order: --geoip / an explicit path, IOTAUDIT_GEOIP, a downloaded file in
    ~/iotaudit, then the copy shipped with the package.
    """
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env = os.environ.get("IOTAUDIT_GEOIP")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.append(user_mmdb_path())
    bundled = bundled_mmdb()
    if bundled is not None:
        candidates.append(bundled)
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.is_file():
            return path
    return None


def month_urls(today: date | None = None) -> list[tuple[str, str]]:
    """This month and the previous month, in case the current file is not out yet."""
    today = today or date.today()
    year, month = today.year, today.month
    out = []
    for _ in range(2):
        stamp = f"{year:04d}-{month:02d}"
        name = f"dbip-country-lite-{stamp}.mmdb.gz"
        url = f"https://download.db-ip.com/free/{name}"
        out.append((stamp, url))
        if month == 1:
            year -= 1
            month = 12
        else:
            month -= 1
    return out


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": DOWNLOAD_UA})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
        return response.read()


def _gunzip(raw: bytes) -> bytes:
    try:
        return gzip.decompress(raw)
    except OSError as exc:
        raise ValueError("downloaded file was not a gzip archive") from exc


def validate_mmdb(path: Path) -> None:
    """Open the file with maxminddb so a truncated download is rejected."""
    try:
        import maxminddb
    except ImportError as exc:
        raise RuntimeError("maxminddb is required to check a country database") from exc
    try:
        reader = maxminddb.open_database(str(path))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"not a usable country database: {exc}") from exc
    try:
        if not getattr(reader, "metadata", None):
            raise ValueError("country database has no metadata")
    finally:
        close = getattr(reader, "close", None)
        if close:
            close()


def database_label(path: Path) -> str | None:
    """Best-effort build date or type from the MMDB metadata, or the file mtime."""
    try:
        import maxminddb

        reader = maxminddb.open_database(str(path))
    except Exception:  # noqa: BLE001
        return None
    try:
        meta = reader.metadata()
        build = getattr(meta, "build_epoch", None)
        if build:
            return datetime.fromtimestamp(int(build), tz=timezone.utc).strftime("%Y-%m")
        kind = getattr(meta, "database_type", None)
        if kind:
            return str(kind)
    except Exception:  # noqa: BLE001
        return None
    finally:
        close = getattr(reader, "close", None)
        if close:
            close()
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m")
    except OSError:
        return None


def source_kind(path: Path) -> str:
    bundled = bundled_mmdb()
    if bundled is not None and path.resolve() == bundled.resolve():
        return "bundled"
    if path.resolve() == user_mmdb_path().resolve():
        return "downloaded"
    return "custom"


def update_mmdb(
    dest: Path | None = None,
    *,
    today: date | None = None,
    fetch=_fetch,
    validate=validate_mmdb,
) -> tuple[Path, str]:
    """Download the latest free DB-IP country lite file to dest.

    Returns (path, YYYY-MM stamp of the file that worked).
    """
    dest = dest or user_mmdb_path()
    dest = dest.expanduser()
    errors: list[str] = []
    for stamp, url in month_urls(today):
        try:
            raw = fetch(url)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                errors.append(f"{stamp} not published yet")
                continue
            raise RuntimeError(f"could not download {url}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not download {url}: {exc.reason}") from exc
        data = _gunzip(raw)
        if not data:
            raise ValueError("downloaded country database was empty")
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="iotaudit-mmdb-", suffix=".mmdb", dir=str(dest.parent))
        tmp = Path(tmp_name)
        try:
            with io.FileIO(fd, "wb") as handle:
                handle.write(data)
            validate(tmp)
            tmp.replace(dest)
        except Exception:
            if tmp.exists():
                tmp.unlink()
            raise
        return dest, stamp
    detail = "; ".join(errors) if errors else "no URL worked"
    raise RuntimeError(f"could not download a DB-IP country lite database ({detail})")
