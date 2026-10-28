#!/usr/bin/env python3
"""Trusted analysis agent copied into an ephemeral VM. Never run on the API host."""
import io
import json
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path, PurePosixPath

WORK = Path("/work")
RESULT = {"completed": False, "project_execution_performed": False, "sboms": [], "steps": [], "gaps": [], "observations": []}
START = time.monotonic()
ENV = dict(os.environ, HTTP_PROXY="http://127.0.0.1:3128", HTTPS_PROXY="http://127.0.0.1:3128", http_proxy="http://127.0.0.1:3128", https_proxy="http://127.0.0.1:3128", NO_PROXY="localhost,127.0.0.1", no_proxy="localhost,127.0.0.1", PIP_DISABLE_PIP_VERSION_CHECK="1", NPM_CONFIG_AUDIT="false", NPM_CONFIG_FUND="false")


def checkpoint():
    temporary = WORK / "checkpoint.next.json"
    temporary.write_text(json.dumps(RESULT))
    temporary.replace(WORK / "checkpoint.json")


def run(args, cwd=None, timeout=240, trace=False, structured=False):
    if trace: RESULT["project_execution_performed"] = True
    remaining = 840 - int(time.monotonic() - START)
    if remaining < 5: raise TimeoutError("job deadline")
    index = len(RESULT["steps"])
    command = ["strace", "-f", "-qq", "-s", "256", "-e", "trace=execve,connect", "-o", str(WORK / f"trace-{index}.log"), *args] if trace else args
    output = WORK / f"step-{index}.log"
    error_output = WORK / f"step-{index}.stderr"
    with output.open("wb") as log, error_output.open("wb") as errors:
        process = subprocess.Popen(command, cwd=cwd, env=ENV, stdout=log, stderr=errors if structured else subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=min(timeout, remaining))
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(process.pid, signal.SIGKILL); process.wait(); code = -9
    tail = (error_output if structured else output).read_bytes()[-8000:].decode("utf-8", "replace")
    RESULT["steps"].append({"command": args[:6], "returncode": code, "tail": tail})
    checkpoint()
    return code, output


def syft(reference, origin):
    code, output = run(["syft", "scan", reference, "-o", "cyclonedx-json"], timeout=180, structured=True)
    if code != 0:
        RESULT["gaps"].append({"reason": "sbom_scan_failed", "file": reference}); return
    try:
        document = json.loads(output.read_bytes())
        RESULT["sboms"].append({"origin": origin, "document": document})
        if reference.startswith("docker:"):
            RESULT.setdefault("scanned_images", []).append({"reference": reference.removeprefix("docker:"), "origin": origin})
        checkpoint()
    except (ValueError, OSError): RESULT["gaps"].append({"reason": "sbom_parse_failed", "file": reference})


def extract():
    root, size = WORK / "source", 0
    root.mkdir()
    with tarfile.open("/home/sca/source.tar.gz", "r:gz") as tar:
        members = tar.getmembers()
        roots = {PurePosixPath(m.name).parts[0] for m in members if PurePosixPath(m.name).parts}
        strip = len(roots) == 1 and any(m.isdir() and len(PurePosixPath(m.name).parts) == 1 for m in members)
        for member in members:
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts: raise ValueError("unsafe archive")
            parts = p.parts[1 if strip else 0:]
            if not parts or any(re.fullmatch(r"\.env.*|\.git|id_rsa|id_ed25519|secrets?", v, re.I) for v in parts): continue
            path = root.joinpath(*parts)
            if member.isdir(): path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                size += member.size
                if size > 256 * 1024 * 1024: raise ValueError("archive size")
                path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, path.open("xb") as target:
                    import shutil
                    shutil.copyfileobj(source, target)
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
    return root


def python_profile(root, config):
    run(["python3", "-m", "venv", str(WORK / "venv")])
    python = str(WORK / "venv/bin/python")
    ENV["PATH"] = str(WORK / "venv/bin") + ":" + ENV.get("PATH", "")
    files = [f for f in config.get("dependency_files", []) if not f.startswith("../") and (WORK / "source" / f).is_file() and re.search(r"requirements.*\.(?:txt|in)$", f, re.I)]
    if not files:
        # Custom requirements paths discovered by static/LLM analysis.
        files = [f for f in config.get("dependency_files", []) if (WORK / "source" / f).is_file() and not f.endswith((".toml", ".lock", ".json", ".cfg", ".py"))][:5]
    if config.get("manifest"):
        manifest = WORK / "source" / config["manifest"]
        if not manifest.resolve().is_relative_to(WORK / "source") or not manifest.is_file(): raise ValueError("invalid manifest")
        files = [config["manifest"]] if not config["manifest"].endswith((".toml", ".cfg", ".py", ".lock")) else []
    else:
        files = sorted(files, key=lambda f: (PurePosixPath(f).name != "requirements.txt", len(PurePosixPath(f).parts), f))[:1]
    for file in files[:8]:
        run([python, "-m", "pip", "install", "-r", str(WORK / "source" / file)], cwd=root, trace=True)
    if not files and (root / "pyproject.toml").exists():
        run([python, "-m", "pip", "install", "."], cwd=root, trace=True)
    elif not files:
        RESULT["gaps"].append({"reason": "no_python_install_profile"})
    if config.get("run_command"):
        run(["/bin/sh", "-lc", config["run_command"]], cwd=root, timeout=120, trace=True)
    else: RESULT["gaps"].append({"reason": "application_runtime_not_requested"})
    code, output = run([python, "-m", "pip", "inspect", "--local"], structured=True)
    if code == 0:
        try:
            data = json.loads(output.read_text())
            installed = data["installed"]
            components, dependencies, refs = [], [], {}
            for item in installed:
                metadata = item["metadata"]; name = metadata["name"].lower().replace("_", "-")
                if name in ("pip", "setuptools", "wheel"): continue
                ref = "pkg:pypi/" + name + "@" + metadata["version"]
                refs[name] = ref; components.append({"type": "library", "name": name, "version": metadata["version"], "purl": ref, "bom-ref": ref})
            roots = []
            for item in installed:
                metadata = item["metadata"]; name = metadata["name"].lower().replace("_", "-")
                if name not in refs: continue
                if item.get("requested"): roots.append(refs[name])
                children = []
                for requirement in metadata.get("requires_dist", []):
                    dep = re.match(r"[A-Za-z0-9_.-]+", requirement)
                    if dep and dep[0].lower().replace("_", "-") in refs:
                        children.append(refs[dep[0].lower().replace("_", "-")])
                dependencies.append({"ref": refs[name], "dependsOn": children})
            dependencies.append({"ref": "application", "dependsOn": roots})
            RESULT["sboms"].append({"origin": "runtime", "document": {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"bom-ref": "application"}}, "components": components, "dependencies": dependencies}})
            RESULT["gaps"].append({"reason": "python_optional_markers_require_review"})
        except (ValueError, KeyError, TypeError): RESULT["gaps"].append({"reason": "python_inventory_parse_failed"})
    else: RESULT["gaps"].append({"reason": "python_inventory_failed"})


def node_profile(root, config):
    run(["npm", "ci" if (root / "package-lock.json").exists() else "install"], cwd=root, trace=True)
    if config.get("run_command"): run(["/bin/sh", "-lc", config["run_command"]], cwd=root, timeout=120, trace=True)
    else: RESULT["gaps"].append({"reason": "application_runtime_not_requested"})
    syft("dir:" + str(root), "runtime")


def docker_profile(root, config):
    override = Path("/etc/systemd/system/docker.service.d/sca-proxy.conf")
    override.parent.mkdir(parents=True, exist_ok=True)
    override.write_text('[Service]\nEnvironment="HTTP_PROXY=http://127.0.0.1:3128" "HTTPS_PROXY=http://127.0.0.1:3128" "NO_PROXY=localhost,127.0.0.1"\n')
    run(["systemctl", "daemon-reload"]); run(["systemctl", "restart", "docker"])
    dockerfile = root / "Dockerfile"
    if not dockerfile.is_file():
        RESULT["gaps"].append({"reason": "dockerfile_not_found"}); return
    unpinned = False
    for pin in config.get("image_pins", []):
        target = WORK / "source" / pin["file"]
        if not target.is_relative_to(WORK / "source") or not target.is_file(): continue
        if not pin.get("resolved"):
            RESULT["gaps"].append({"reason": "base_image_not_pinned", "file": pin["file"]}); unpinned = True; continue
        lines = target.read_text().splitlines()
        index = pin["line"] - 1
        if 0 <= index < len(lines):
            match = re.match(r"(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+)(.*)", lines[index], re.I)
            if not match or match[2] != pin.get("source_reference", pin["reference"]):
                raise ValueError("base image evidence changed")
            lines[index] = match[1] + pin["resolved"] + match[3]
            target.write_text("\n".join(lines) + "\n")
    if unpinned: return
    stages, aliases = [], set()
    for line in dockerfile.read_text().splitlines():
        match = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not match: continue
        ref, stage = match.groups()
        if ref not in aliases and ref != "scratch" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]*", ref):
            if "@sha256:" not in ref:
                RESULT["gaps"].append({"reason": "base_image_not_pinned"}); return
            if run(["docker", "pull", ref], timeout=180)[0] == 0:
                syft("docker:" + ref, "base_image")
        elif "$" in ref: RESULT["gaps"].append({"reason": "dynamic_base_image_reference"})
        if stage: aliases.add(stage); stages.append(stage)
    tag = "sca-analysis:result"
    base = ["docker", "build", "--network", "host", "--build-arg", "HTTP_PROXY=http://127.0.0.1:3128", "--build-arg", "HTTPS_PROXY=http://127.0.0.1:3128", "--build-arg", "http_proxy=http://127.0.0.1:3128", "--build-arg", "https_proxy=http://127.0.0.1:3128"]
    if run(base + ["-t", tag, "."], cwd=root, timeout=360, trace=True)[0] != 0:
        RESULT["gaps"].append({"reason": "docker_build_failed"}); return
    syft("docker:" + tag, "build")
    for index, stage in enumerate(stages[:3]):
        image = "sca-analysis:stage-" + str(index)
        if run(base + ["--target", stage, "-t", image, "."], cwd=root, timeout=180)[0] == 0: syft("docker:" + image, "build")
    if config.get("run_command"):
        run(["docker", "create", "--network", "host", "--name", "sca-observed", "-e", "HTTP_PROXY=http://127.0.0.1:3128", "-e", "HTTPS_PROXY=http://127.0.0.1:3128", "-e", "http_proxy=http://127.0.0.1:3128", "-e", "https_proxy=http://127.0.0.1:3128", tag, "/bin/sh", "-lc", config["run_command"]])
        run(["docker", "start", "-a", "sca-observed"], timeout=120, trace=True)
        run(["docker", "stop", "-t", "2", "sca-observed"])
        code, output = run(["docker", "diff", "sca-observed"])
        RESULT["observations"] = output.read_text(errors="replace").splitlines()[:200]
        if run(["docker", "commit", "sca-observed", "sca-analysis:runtime"])[0] == 0: syft("docker:sca-analysis:runtime", "runtime")
    else: RESULT["gaps"].append({"reason": "application_runtime_not_requested"})


def main():
    WORK.mkdir(exist_ok=True)
    config = json.loads(Path("/home/sca/config.json").read_text())
    try:
        source = extract()
        root = (source / config.get("subpath", "")).resolve()
        if not root.is_relative_to(source): raise ValueError("invalid subpath")
        {"python": python_profile, "node": node_profile, "docker": docker_profile}[config["profile"]](root, config)
        RESULT["completed"] = not any(s["returncode"] != 0 for s in RESULT["steps"])
    except Exception as error:
        RESULT["gaps"].append({"reason": "guest_analysis_incomplete", "error_type": type(error).__name__})
    traces = []
    for path in sorted(WORK.glob("trace-*.log")):
        with path.open(errors="replace") as f:
            for line in f:
                if len(traces) >= 300: break
                if "execve(" in line or "connect(" in line: traces.append(line.strip()[:500])
    RESULT["process_observations"] = traces
    RESULT["elapsed_seconds"] = round(time.monotonic() - START, 2)
    (WORK / "report.json").write_text(json.dumps(RESULT))

if __name__ == "__main__": main()
