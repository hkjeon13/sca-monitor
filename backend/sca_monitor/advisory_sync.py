from __future__ import annotations

import json
import socket
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator
from uuid import uuid4
from urllib.request import Request, urlopen

from .app import ScaMonitorApp

OSV_DUMP_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"


@dataclass(frozen=True)
class OsvSyncResult:
    source: str
    ecosystem: str
    processed: int
    imported_rows: int
    failed: int
    dump_url: str


def osv_dump_url(ecosystem: str) -> str:
    if not ecosystem:
        raise ValueError("ecosystem required")
    return f"{OSV_DUMP_BASE_URL}/{ecosystem}/all.zip"


def sync_osv_ecosystem_dump(
    app: ScaMonitorApp,
    ecosystem: str,
    *,
    limit: int | None = None,
    dump_url: str | None = None,
    zip_path: Path | None = None,
    lock_owner: str | None = None,
    lock_ttl_seconds: int = 3600,
) -> OsvSyncResult:
    url = dump_url or osv_dump_url(ecosystem)
    processed = 0
    imported_rows = 0
    failed = 0
    owner = lock_owner or default_lock_owner(ecosystem)

    try:
        with app.advisory_sync_lock("OSV", owner, ttl_seconds=lock_ttl_seconds):
            for payload in iter_osv_dump_payloads(url=url, zip_path=zip_path):
                if limit is not None and processed >= limit:
                    break
                processed += 1
                try:
                    imported_rows += app.import_osv_payload(payload)
                except Exception:
                    failed += 1
            status = "ok" if failed == 0 else "partial"
            app.record_advisory_sync("OSV", status, f"{ecosystem}:dump", None, imported_count=0)
    except Exception as exc:
        app.record_advisory_sync("OSV", "error", f"{ecosystem}:dump", str(exc), imported_count=0)
        raise

    return OsvSyncResult(
        source="OSV",
        ecosystem=ecosystem,
        processed=processed,
        imported_rows=imported_rows,
        failed=failed,
        dump_url=url,
    )


def default_lock_owner(ecosystem: str) -> str:
    return f"osv-sync:{ecosystem}:{socket.gethostname()}:{uuid4()}"


def iter_osv_dump_payloads(*, url: str, zip_path: Path | None = None) -> Iterator[dict]:
    if zip_path is not None:
        yield from iter_zip_payloads(zip_path)
        return

    with tempfile.NamedTemporaryFile(suffix=".zip") as temp_file:
        download_file(url, Path(temp_file.name))
        yield from iter_zip_payloads(Path(temp_file.name))


def download_file(url: str, path: Path, opener: Callable | None = None) -> None:
    request = Request(url, headers={"Accept": "application/zip", "User-Agent": "sca-monitor/0.1"})
    open_url = opener or urlopen
    with open_url(request, timeout=60) as response:
        with path.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)


def iter_zip_payloads(path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(path) as archive:
        for name in sorted(archive.namelist()):
            if not name.endswith(".json"):
                continue
            with archive.open(name) as entry:
                yield json.loads(entry.read().decode("utf-8"))
