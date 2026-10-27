#!/usr/bin/env python3
"""Serialize source ingestion to avoid concurrent SQLite writers and report progress."""

import fcntl
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings


def main():
    settings = load_settings(component="worker")
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with (settings.data_dir / "source-sync.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Source sync already running")
            return 0
        jobs = [
            ("CISA_KEV", ["scripts/cisa_kev_sync.py"]),
            ("GHSA", ["scripts/ghsa_incremental.py"]),
        ]
        for ecosystem in os.getenv("SCA_MONITOR_OSV_ECOSYSTEMS", "npm").split(","):
            if ecosystem.strip():
                jobs.append(
                    (
                        "OSV",
                        [
                            "scripts/osv_sync.py",
                            "--ecosystem",
                            ecosystem.strip(),
                            "--lock-ttl-seconds",
                            "21600",
                        ],
                    )
                )
        jobs.append(
            (
                "OpenSSF",
                [
                    "scripts/osv_sync.py",
                    "--ecosystem",
                    "npm",
                    "--source",
                    "OpenSSF",
                    "--malicious-only",
                    "--lock-ttl-seconds",
                    "21600",
                ],
            )
        )
        delay = "0.7" if os.getenv("NVD_API_KEY") else "6.2"
        jobs.append(
            (
                "NVD",
                [
                    "scripts/nvd_cve_sync.py",
                    "--use-cursor",
                    "--lookback-hours",
                    "24",
                    "--delay-seconds",
                    delay,
                ],
            )
        )
        progress = settings.data_dir / "source-sync-progress.json"
        failures = []
        for source, args in jobs:
            now = datetime.now(timezone.utc).isoformat()
            temporary = progress.with_suffix(".new")
            temporary.write_text(
                json.dumps(
                    {
                        "source": source,
                        "status": "running",
                        "pid": os.getpid(),
                        "started_at": now,
                    }
                )
            )
            temporary.replace(progress)
            print("Starting", source, now, flush=True)
            try:
                result = subprocess.run(
                    [sys.executable, *args], timeout=21600, check=False
                )
                if result.returncode:
                    raise RuntimeError(f"source process exited {result.returncode}")
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                failures.append(source)
                ScaMonitorApp(settings).record_advisory_sync(
                    source, "error", "scheduled-sync", str(exc)
                )
            print("Finished", source, flush=True)
        temporary = progress.with_suffix(".new")
        temporary.write_text(
            json.dumps(
                {
                    "status": "complete",
                    "failed_sources": failures,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        )
        temporary.replace(progress)
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
