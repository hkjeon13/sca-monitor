"""Host-side controller: untrusted commands execute only beyond the KVM boundary."""
from __future__ import annotations

import json
import os
import re
import select
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .scanner import redact
from .transport import public_addresses, RepositoryError

DEFAULT_HOSTS = "pypi.org,files.pythonhosted.org,registry.npmjs.org,registry.yarnpkg.com,registry-1.docker.io,auth.docker.io,production.cloudflare.docker.com,production.cloudfront.docker.com,archive.ubuntu.com,security.ubuntu.com,deb.debian.org,security.debian.org,dl-cdn.alpinelinux.org"


class EgressProxy(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        self.events, self.connections = [], threading.BoundedSemaphore(24)
        self.allowed = set(filter(None, os.getenv("SCA_SANDBOX_EGRESS_HOSTS", DEFAULT_HOSTS).split(",")))
        super().__init__(("127.0.0.1", 0), ProxyHandler)

    def record(self, host, allowed):
        if len(self.events) < 300: self.events.append({"host": redact(host)[:200], "allowed": allowed})


class ProxyHandler(BaseHTTPRequestHandler):
    timeout = 20
    def log_message(self, *args): pass

    def target(self, host, port):
        if host not in self.server.allowed or port not in (80, 443):
            self.server.record(host or "invalid", False)
            raise RepositoryError("egress denied")
        addresses = public_addresses(host, port)
        raw = socket.socket(addresses[0][0], socket.SOCK_STREAM)
        raw.settimeout(20); raw.connect(addresses[0][4])
        self.server.record(host, True)
        return raw

    def relay(self, upstream):
        sockets, until, transferred = [self.connection, upstream], time.monotonic() + 300, 0
        while time.monotonic() < until and transferred < 512 * 1024 * 1024:
            available, _, _ = select.select(sockets, [], [], 20)
            if not available: return
            for source in available:
                chunk = source.recv(65536)
                if not chunk: return
                transferred += len(chunk)
                (upstream if source is self.connection else self.connection).sendall(chunk)

    def do_CONNECT(self):
        if not self.server.connections.acquire(blocking=False): self.send_error(503); return
        try:
            parsed = urlsplit("https://" + self.path)
            if parsed.username or parsed.password or parsed.path or parsed.query: raise RepositoryError("invalid tunnel")
            with self.target(parsed.hostname, parsed.port or 443) as upstream:
                self.send_response(200); self.end_headers(); self.wfile.flush()
                self.relay(upstream)
        except (OSError, ValueError):
            try: self.send_error(403)
            except OSError: pass
        finally: self.server.connections.release()

    def do_GET(self):
        if not self.server.connections.acquire(blocking=False): self.send_error(503); return
        try:
            parsed = urlsplit(self.path)
            if parsed.scheme != "http" or parsed.username or parsed.password: raise RepositoryError("invalid proxy request")
            with self.target(parsed.hostname, parsed.port or 80) as upstream:
                path = parsed.path or "/"
                if parsed.query: path += "?" + parsed.query
                upstream.sendall((f"GET {path} HTTP/1.0\r\nHost: {parsed.hostname}\r\nConnection: close\r\n\r\n").encode())
                until, transferred = time.monotonic() + 300, 0
                while time.monotonic() < until and transferred < 512 * 1024 * 1024:
                    data = upstream.recv(65536)
                    if not data: break
                    transferred += len(data)
                    self.wfile.write(data)
        except (OSError, ValueError):
            try: self.send_error(403)
            except OSError: pass
        finally: self.server.connections.release()


def checked(command, timeout=30, **kwargs):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **kwargs)


def redact_document(value):
    if isinstance(value, dict): return {k: redact_document(v) for k, v in value.items()}
    if isinstance(value, list): return [redact_document(v) for v in value]
    return redact(value) if isinstance(value, str) else value


def bounded_guest_read(command, maximum=20 * 1024 * 1024):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    until, chunks, size = time.monotonic() + 30, [], 0
    try:
        while time.monotonic() < until:
            ready, _, _ = select.select([process.stdout], [], [], 1)
            if not ready: continue
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk: return b"".join(chunks)
            size += len(chunk)
            if size > maximum: raise RepositoryError("심층 리포트 크기 한도를 초과했습니다.")
            chunks.append(chunk)
        raise RepositoryError("심층 리포트 수집 시간이 초과되었습니다.")
    finally:
        if process.poll() is None: process.terminate()
        process.wait(timeout=5)


def run_sandbox(job, snapshot, archive, heartbeat):
    sid = job["id"]
    if not re.fullmatch(r"[0-9a-f-]{36}", sid): raise RepositoryError("잘못된 작업 ID입니다.")
    ready_path = Path(os.getenv("SCA_SANDBOX_READY_FILE", str(archive.parents[2] / "sandbox-ready.json")))
    if not ready_path.is_file(): raise RepositoryError("격리 VM 워커가 준비되지 않았습니다.")
    ready = json.loads(ready_path.read_text())
    if ready.get("isolation") != "kvm" or not os.access("/dev/kvm", os.R_OK | os.W_OK): raise RepositoryError("KVM 격리를 확인하지 못했습니다.")
    vmroot = Path(ready["jobs_root"]) / sid
    vmroot.mkdir(mode=0o700)
    key = archive.parent / "sandbox-ssh-key"
    checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    public = key.with_suffix(".pub").read_text().strip()
    (vmroot / "user-data").write_text("#cloud-config\n" + json.dumps({"users": [{"name": "sca", "sudo": "ALL=(ALL) NOPASSWD:ALL", "shell": "/bin/bash", "ssh_authorized_keys": [public]}], "ssh_pwauth": False, "package_update": False, "runcmd": [["sh", "-c", "touch /var/lib/sca-job.ready"]]}))
    (vmroot / "meta-data").write_text("instance-id: " + sid + "\nlocal-hostname: sca-analysis\n")
    checked(["cloud-localds", str(vmroot / "seed.iso"), str(vmroot / "user-data"), str(vmroot / "meta-data")])
    checked(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", ready["base_image"], str(vmroot / "root.qcow2")])
    helper = ready["launcher"]
    proxy = EgressProxy()
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
    with socket.socket() as chosen: chosen.bind(("127.0.0.1", 0)); port = chosen.getsockname()[1]
    ssh = ["ssh", "-i", str(key), "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + str(archive.parent / "sandbox-known-hosts"), "sca@127.0.0.1"]
    scp = ["scp", "-q", "-i", str(key), "-P", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(archive.parent / "sandbox-known-hosts")]
    tunnel = None
    try:
        checked(["sudo", "-n", helper, "start", sid, str(port), str(proxy.server_port)])
        deadline = time.monotonic() + 180
        while True:
            heartbeat("sandbox_preparing")
            try:
                probe = subprocess.run(ssh + ["test -f /var/lib/sca-job.ready"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
                if probe.returncode == 0: break
            except subprocess.TimeoutExpired:
                pass
            if time.monotonic() > deadline: raise RepositoryError("격리 VM 준비 시간이 초과되었습니다.")
            time.sleep(2)
        # Fixed reverse forwarding exposes only this job's restricted proxy.
        # The guest has no general route to host services or the internet.
        tunnel = subprocess.Popen(ssh[:-1] + ["-N", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=5", "-R", f"127.0.0.1:3128:127.0.0.1:{proxy.server_port}", ssh[-1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if tunnel.poll() is not None: raise RepositoryError("격리 분석 프록시 연결을 준비하지 못했습니다.")
        agent = Path(__file__).resolve().parents[3] / "scripts/sandbox_guest.py"
        config = archive.parent / "sandbox-config.json"
        config.write_text(json.dumps({k: snapshot.get(k, "") for k in ("profile", "subpath", "run_command", "manifest", "dependency_files", "image_pins")}))
        checked(scp + [str(archive), str(agent), str(config), "sca@127.0.0.1:/home/sca/"], timeout=60)
        # The filenames are fixed, and only this command crosses the SSH boundary.
        checked(ssh + ["cp /home/sca/sandbox-config.json /home/sca/config.json"], timeout=10)
        heartbeat("sandbox_building")
        process = subprocess.Popen(ssh + ["sudo -n python3 /home/sca/sandbox_guest.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 900
        try:
            while process.poll() is None:
                heartbeat("sandbox_observing")
                if time.monotonic() > deadline: raise RepositoryError("심층 분석 실행 시간 한도를 초과했습니다.")
                time.sleep(2)
            raw = bounded_guest_read(ssh + ["sudo -n cat /work/report.json"])
        finally:
            if process.poll() is None: process.terminate(); process.wait(timeout=10)
        if len(raw) > 20 * 1024 * 1024: raise RepositoryError("심층 리포트 크기 한도를 초과했습니다.")
        result = json.loads(raw)
        if not isinstance(result, dict) or not isinstance(result.get("sboms"), list): raise RepositoryError("심층 리포트 형식이 올바르지 않습니다.")
        # Guest output is untrusted data, not an instruction to execute host tools.
        result["steps"] = [{"command": [redact(str(v))[:300] for v in step.get("command", [])[:6]], "returncode": step.get("returncode"), "tail": redact(str(step.get("tail", "")))[:3000]} for step in result.get("steps", [])[:100]]
        result["process_observations"] = [redact(str(v))[:500] for v in result.get("process_observations", [])[:300]]
        result["network_observations"] = proxy.events
        result["isolation"] = "kvm"
        result["network_policy"] = "restricted registry proxy; direct guest egress blocked"
        return result
    except Exception:
        # Recover only bounded evidence; never allow guest output to trigger host actions.
        try:
            raw = bounded_guest_read(ssh + ["sudo -n cat /work/checkpoint.json"])
            partial = json.loads(raw)
            if isinstance(partial, dict) and isinstance(partial.get("sboms"), list):
                partial["completed"] = False
                partial["network_observations"] = proxy.events
                with (archive.parent / "sandbox-partial.json").open("x", encoding="utf-8") as saved:
                    json.dump(redact_document(partial), saved)
                (archive.parent / "sandbox-partial.json").chmod(0o600)
        except Exception:
            pass
        raise
    finally:
        subprocess.run(["sudo", "-n", helper, "stop", sid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        if tunnel is not None and tunnel.poll() is None:
            tunnel.terminate(); tunnel.wait(timeout=5)
        proxy.shutdown(); proxy.server_close(); thread.join(timeout=3)
