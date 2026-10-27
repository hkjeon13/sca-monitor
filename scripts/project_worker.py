#!/usr/bin/env python3
"""Poll project inventories and deliver only explicitly configured project alerts."""

import fcntl
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.alert_dispatch import dispatch_pending_alerts
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings
from backend.sca_monitor.endpoint_poll import poll_configured_endpoints

settings = load_settings(component="worker")
with (settings.data_dir / "project-worker.lock").open("a") as lock:
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(0)
    app = ScaMonitorApp(settings)
    polled = poll_configured_endpoints(app, limit=50)
    delivered = dispatch_pending_alerts(
        app, webhook_url=None, limit=50, project_only=True
    )
    print(json.dumps({"poll": polled.__dict__, "alerts": delivered.__dict__}))
