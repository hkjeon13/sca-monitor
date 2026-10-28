#!/usr/bin/python3
"""Install root-owned outside the repo. Only launch/stop a UUID-scoped KVM unit."""
import grp
import os
import pwd
import re
import subprocess
import shutil
import sys
from pathlib import Path

ROOT = Path("/data/sca-monitor-sandbox")


def main():
    if os.getuid() != 0: raise SystemExit("root launcher required")
    action, sid = sys.argv[1:3]
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", sid): raise SystemExit("invalid job id")
    unit = "sca-monitor-sandbox-" + sid
    if action == "stop":
        return subprocess.run(["systemctl", "stop", unit], check=False).returncode
    if action != "start" or len(sys.argv) != 5: raise SystemExit("invalid action")
    allocated = sum(p.stat().st_blocks * 512 for p in (ROOT / "jobs").glob("*/root.qcow2") if not p.is_symlink())
    if allocated > 32 * 1024**3 or shutil.disk_usage(ROOT).free < 8 * 1024**3: raise SystemExit("sandbox disk budget reached; retained artifacts require operator review")
    ssh, proxy = map(int, sys.argv[3:])
    if not (20000 <= ssh <= 65535 and 20000 <= proxy <= 65535 and ssh != proxy): raise SystemExit("invalid ports")
    directory = ROOT / "jobs" / sid
    account = pwd.getpwnam("sca-analysis")
    if directory.is_symlink() or directory.resolve() != directory or not directory.is_dir(): raise SystemExit("invalid job directory")
    for name in ("root.qcow2", "seed.iso"):
        path = directory / name
        if path.is_symlink() or not path.is_file(): raise SystemExit("invalid job file")
        os.chown(path, account.pw_uid, account.pw_gid); path.chmod(0o600 if name == "root.qcow2" else 0o400)
    console = directory / "console.log"
    fd = os.open(console, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
    os.chown(console, account.pw_uid, account.pw_gid)
    os.chown(directory, 0, account.pw_gid); directory.chmod(0o750)
    properties = ["ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes", "ProtectProc=invisible", "RestrictSUIDSGID=yes", "MemoryMax=4G", "CPUQuota=200%", "TasksMax=64", "RuntimeMaxSec=1100", "TimeoutStopSec=5", "IPAddressDeny=any", "IPAddressAllow=localhost", "InaccessiblePaths=/home /root /run/user -/var/lib/docker -/var/lib/lxd -/var/lib/containers", "TemporaryFileSystem=/data:ro", "BindReadOnlyPaths=" + str(ROOT / "runner-base.qcow2"), "BindPaths=" + str(directory), "ReadWritePaths=" + str(directory)]
    properties.append("LimitFSIZE=8G")
    properties += ["DevicePolicy=closed", "DeviceAllow=/dev/kvm rw"]
    args = ["systemd-run", "--quiet", "--unit=" + unit, "--uid=sca-analysis", "--collect"]
    for item in properties: args += ["--property=" + item]
    args += ["/usr/bin/qemu-system-x86_64", "-enable-kvm", "-machine", "q35", "-cpu", "host", "-m", "2560", "-smp", "2", "-display", "none", "-monitor", "none", "-serial", "file:" + str(console), "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny", "-drive", "file=" + str(directory / "root.qcow2") + ",if=virtio,format=qcow2", "-drive", "file=" + str(directory / "seed.iso") + ",media=cdrom,readonly=on", "-netdev", f"user,id=n,restrict=on,hostfwd=tcp:127.0.0.1:{ssh}-:22", "-device", "virtio-net-pci,netdev=n", "-device", "virtio-rng-pci"]
    return subprocess.run(args, check=False).returncode

if __name__ == "__main__": raise SystemExit(main())
