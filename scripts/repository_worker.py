#!/usr/bin/env python3
"""Process one repository analysis job per invocation; systemd bounds concurrency."""
import fcntl
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings
from backend.sca_monitor.repository.worker import RepositoryWorker

def main():
    settings = load_settings(component="worker")
    with (settings.data_dir / "repository-worker.lock").open("a") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return 0
        app = ScaMonitorApp(settings)
        print(json.dumps(RepositoryWorker(app).run_once(), ensure_ascii=False))
    return 0

if __name__ == "__main__": raise SystemExit(main())
