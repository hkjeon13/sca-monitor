#!/usr/bin/env python3
"""Generate a single-use administrator setup link without setting a password."""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.sca_monitor.app import ScaMonitorApp
from backend.sca_monitor.config import load_settings

parser = argparse.ArgumentParser()
parser.add_argument("--public-url", required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
app = ScaMonitorApp(load_settings())
token = app.workspace.make_setup_token(admin=True)
args.output.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as file:
    file.write(args.public_url.rstrip("/") + "/#setup=" + token + "\n")
print(f"Administrator setup link saved to {args.output} (expires in 24 hours).")
