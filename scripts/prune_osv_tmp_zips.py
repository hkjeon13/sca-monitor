#!/usr/bin/env python3
"""Retain recent orphaned OSV download ZIPs in one explicit directory."""

import argparse
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


NAME = re.compile(r"tmp[a-z0-9_]{8}\.zip\Z")
DEFAULT_DIRECTORY = Path(__file__).resolve().parent.parent


def inventory(directory_fd: int) -> list[dict]:
    entries = []
    with os.scandir(directory_fd) as scan:
        for entry in scan:
            if not NAME.fullmatch(entry.name):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                continue
            entries.append({
                "name": entry.name,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
            })
    return sorted(entries, key=lambda item: (item["mtime_ns"], item["name"]), reverse=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--keep", type=int, default=10)
    parser.add_argument("--minimum-age-hours", type=float, default=24)
    parser.add_argument("--apply", action="store_true", help="Delete selected files; otherwise only report")
    parser.add_argument("--manifest", type=Path, help="Exclusive JSON manifest path (default: .data/tmp-zip-prune-UTC-pid.json)")
    args = parser.parse_args()
    if args.keep < 1 or args.minimum_age_hours < 1:
        parser.error("--keep and --minimum-age-hours must both be positive")
    if not args.apply and args.manifest is not None:
        parser.error("--manifest requires --apply")

    directory = args.directory.absolute()
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        files = inventory(directory_fd)
        retained = files[:args.keep]
        cutoff_ns = time.time_ns() - int(args.minimum_age_hours * 3600 * 1_000_000_000)
        selected = [item for item in files[args.keep:] if item["mtime_ns"] < cutoff_ns]
        report = {
            "directory": str(directory),
            "keep": args.keep,
            "minimum_age_hours": args.minimum_age_hours,
            "matched_count": len(files),
            "retained": retained,
            "selected": selected,
            "selected_count": len(selected),
            "selected_bytes": sum(item["size"] for item in selected),
        }
        if not args.apply:
            print(json.dumps({key: value for key, value in report.items() if key != "selected"}, ensure_ascii=False))
            return 0

        manifest_path = args.manifest or directory / ".data" / f"tmp-zip-prune-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{os.getpid()}.json"
        manifest_fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(manifest_fd, "w", encoding="utf-8") as manifest:
            json.dump(report, manifest, ensure_ascii=False, indent=2)
            manifest.write("\n")
            manifest.flush()
            os.fsync(manifest.fileno())

        deleted_count = 0
        deleted_bytes = 0
        skipped = []
        for item in selected:
            try:
                current = os.stat(item["name"], dir_fd=directory_fd, follow_symlinks=False)
                if (not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                        or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                        != (item["device"], item["inode"], item["size"], item["mtime_ns"])):
                    skipped.append(item["name"])
                    continue
                os.unlink(item["name"], dir_fd=directory_fd)
                deleted_count += 1
                deleted_bytes += item["size"]
            except FileNotFoundError:
                skipped.append(item["name"])
        print(json.dumps({
            "directory": str(directory), "manifest": str(manifest_path),
            "matched_count": len(files), "retained_count": len(retained),
            "selected_count": len(selected), "deleted_count": deleted_count,
            "deleted_bytes": deleted_bytes, "skipped": skipped,
        }, ensure_ascii=False))
        return 0 if not skipped else 1
    finally:
        os.close(directory_fd)


if __name__ == "__main__":
    sys.exit(main())
