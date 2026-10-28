"""Evidence-based, non-executing repository analysis. Repository files are data."""
from __future__ import annotations

import ast
import configparser
import io
import json
import posixpath
import re
import tarfile
import uuid
from pathlib import PurePosixPath
from urllib.parse import unquote

try:
    import tomllib
except ImportError:
    import tomli as tomllib
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

MAX_FILES, MAX_TEXT, MAX_FILE, MAX_COMPONENTS = 3000, 12_000_000, 1_000_000, 10000
SECRET_NAME = re.compile(r"(^|/)(\.git|\.env[^/]*|id_rsa|id_ed25519|credentials|secrets?)(/|$)|\.(pem|key|p12)$", re.I)
INSTALL = re.compile(r"\b(pip3?\s+install|python[\w. /-]*-m\s+pip\s+install|npm\s+(?:i|install|ci)|pnpm\s+(?:i|install)|yarn\s+(?:add|install)|apt(?:-get)?\s+install|apk\s+add|dnf\s+install|curl\b.*\|\s*(?:ba)?sh|wget\b.*\|\s*(?:ba)?sh|subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system|exec\(|eval\(|b64decode)", re.I)


def archive_files(content, subpath=""):
    files, gaps, size = {}, [], 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        members, expanded = [], 0
        for member in archive:
            expanded += member.size
            if expanded > 256 * 1024 * 1024:
                raise ValueError("저장소 압축 해제 크기 제한을 초과했습니다.")
            if len(members) >= 30000:
                gaps.append({"reason": "archive_entry_limit"}); break
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise ValueError("저장소 압축 파일의 경로가 올바르지 않습니다.")
            members.append(member)
        roots = {PurePosixPath(m.name).parts[0] for m in members if PurePosixPath(m.name).parts}
        strip = len(roots) == 1 and any(m.isdir() and len(PurePosixPath(m.name).parts) == 1 for m in members)
        for member in members:
            parts = PurePosixPath(member.name).parts[1 if strip else 0:]
            name = "/".join(parts)
            if not name or SECRET_NAME.search(name):
                continue
            if subpath and not name.startswith(subpath.rstrip("/") + "/"):
                continue
            if member.issym() or member.islnk():
                gaps.append({"file": name, "reason": "symlink_not_followed"}); continue
            if not member.isfile():
                continue
            if member.size > MAX_FILE:
                gaps.append({"file": name, "reason": "file_size_limit"}); continue
            if len(files) >= MAX_FILES or size + member.size > MAX_TEXT:
                gaps.append({"reason": "text_scan_limit"}); break
            with archive.extractfile(member) as source:
                raw = source.read(MAX_FILE + 1)
            if b"\x00" in raw:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            files[name] = text
            size += len(raw)
    return files, gaps


class Analyzer:
    def __init__(self, scan_id, files):
        self.scan_id, self.files = scan_id, files
        self.components, self.edges, self.gaps, self.events, self.images = {}, set(), [], [], []
        self.documents, self.requirements_seen = [], set()

    def add(self, ecosystem, name, version, module, file, line=1, relationship="direct", origin="repository", declared_range=None, scope="production", context=""):
        name = canonicalize_name(name) if ecosystem == "PyPI" else name.strip()
        key = (ecosystem, name, version or declared_range or "?", module, origin, context)
        cid = str(uuid.uuid5(uuid.UUID(self.scan_id), json.dumps(key)))
        if cid not in self.components and len(self.components) >= MAX_COMPONENTS:
            raise ValueError("패키지 수 제한을 초과했습니다.")
        evidence = {"file": file, "line": line, "scope": scope}
        if cid in self.components:
            if evidence not in self.components[cid]["evidence"]:
                self.components[cid]["evidence"].append(evidence)
        else:
            self.components[cid] = {"id": cid, "ecosystem": ecosystem, "name": name, "version": version, "declared_range": declared_range, "module": module or ".", "origin": origin, "relationship": relationship, "evidence": [evidence], "purl": f"pkg:{'pypi' if ecosystem == 'PyPI' else ecosystem.lower()}/{name}@{version}" if version else None}
        if relationship == "direct":
            self.components[cid]["relationship"] = "direct"
        return cid

    def gap(self, file, reason):
        self.gaps.append({"file": file, "reason": reason})

    def requirement(self, value, file, line=1, scope="production", constraints=None, module=None):
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        value = re.sub(r"\s+--hash=\S+", "", value)
        if not value or value.startswith("#"):
            return
        try:
            req = Requirement(value)
        except InvalidRequirement:
            self.gap(file, f"requirement_unresolved:line={line}"); return
        if req.url:
            self.gap(file, f"direct_url_dependency:line={line}")
        exact = [s.version for s in req.specifier if s.operator in ("==", "===") and "*" not in s.version]
        version = exact[0] if len(exact) == 1 else (constraints or {}).get(canonicalize_name(req.name))
        if version and req.specifier and not req.specifier.contains(version, prereleases=True):
            version = None
        cid = self.add("PyPI", req.name, version, posixpath.dirname(file) if module is None else module, file, line, declared_range=str(req.specifier) or req.url or "unresolved", scope=scope)
        if req.marker:
            self.components[cid]["evidence"][-1]["marker"] = str(req.marker)

    def requirements(self, file, scope=None, constraints=None, stack=(), module=None):
        if file in stack:
            self.gap(file, "requirements_include_cycle"); return
        if file not in self.files:
            self.gap(file, "referenced_file_not_available"); return
        scope = scope or ("development" if re.search(r"dev|test", file, re.I) else "production")
        module = posixpath.dirname(file) if module is None else module
        marker = (file, scope, module)
        if marker in self.requirements_seen:
            return
        self.requirements_seen.add(marker)
        self.documents.append(file)
        local = dict(constraints or {})
        lines = self.files[file].replace("\\\n", " ").splitlines()
        for number, line in enumerate(lines, 1):
            match = re.match(r"\s*(?:-c\s*|--constraint(?:=|\s+))([^\s#]+)", line)
            if match:
                name = posixpath.normpath(posixpath.join(posixpath.dirname(file), match[1]))
                if name.startswith("../") or name.startswith("/") or name not in self.files:
                    self.gap(file, "constraint_unavailable"); continue
                for item in self.files[name].splitlines():
                    try:
                        req = Requirement(item.split(" #", 1)[0].strip())
                        pinned = [s.version for s in req.specifier if s.operator == "==" and "*" not in s.version]
                        if len(pinned) == 1: local[canonicalize_name(req.name)] = pinned[0]
                    except InvalidRequirement: pass
        for number, line in enumerate(lines, 1):
            match = re.match(r"\s*(?:-r\s*|--requirement(?:=|\s+))([^\s#]+)", line)
            if match:
                name = posixpath.normpath(posixpath.join(posixpath.dirname(file), match[1]))
                if name.startswith("../") or name.startswith("/"):
                    self.gap(file, "include_outside_repository"); continue
                self.requirements(name, scope, local, stack + (file,), module)
            elif line.strip().startswith("-"):
                if not re.match(r"\s*(?:-c\s*|--constraint(?:=|\s+))", line): self.gap(file, f"requirement_option_unresolved:line={number}")
            else:
                self.requirement(line, file, number, scope, local, module)

    def toml(self, file):
        try:
            data = tomllib.loads(self.files[file])
        except (ValueError, TypeError):
            self.gap(file, "toml_parse_failed"); return
        project = data.get("project", {})
        values = [(v, "production") for v in project.get("dependencies", [])]
        for group, items in project.get("optional-dependencies", {}).items():
            values += [(v, "development" if group in ("dev", "test") else "optional:" + group) for v in items if isinstance(v, str)]
        for group, items in data.get("dependency-groups", {}).items():
            values += [(v, "development:" + group) for v in items if isinstance(v, str)]
            if any(not isinstance(v, str) for v in items): self.gap(file, "dependency_group_include_requires_review")
        for v in data.get("build-system", {}).get("requires", []): values.append((v, "build"))
        poetry = data.get("tool", {}).get("poetry", {})
        groups = [(poetry.get("dependencies", {}), "production"), (poetry.get("dev-dependencies", {}), "development")]
        groups += [(g.get("dependencies", {}), "development:" + name) for name, g in poetry.get("group", {}).items()]
        for dependencies, scope in groups:
            for name, spec in dependencies.items():
                if name.lower() == "python": continue
                spec = spec.get("version", "*") if isinstance(spec, dict) else spec
                normalized = "==" + spec if isinstance(spec, str) and re.fullmatch(r"\d[\w.+-]*", spec) else spec
                if isinstance(normalized, str) and not normalized.startswith(("^", "~", "*")):
                    values.append((name + normalized, scope))
                else:
                    self.add("PyPI", name, None, posixpath.dirname(file), file, declared_range=str(spec), scope=scope)
        for value, scope in values:
            self.requirement(value, file, scope=scope)
        if values or poetry:
            self.documents.append(file)
        if project.get("dynamic"):
            self.gap(file, "dynamic_project_metadata")
        packages = data.get("package", [])
        if isinstance(packages, list):
            by_name = {}
            for package in packages:
                if not isinstance(package, dict) or not package.get("name") or not package.get("version"): continue
                cid = self.add("PyPI", package["name"], package["version"], posixpath.dirname(file), file, relationship="unknown")
                by_name.setdefault(canonicalize_name(package["name"]), []).append(cid)
            for package in packages:
                if not isinstance(package, dict) or not package.get("name"): continue
                parents = by_name.get(canonicalize_name(package["name"]), [])
                dependencies = package.get("dependencies", {})
                for dependency in dependencies:
                    name = dependency.get("name") if isinstance(dependency, dict) else dependency
                    children = by_name.get(canonicalize_name(name), [])
                    if len(parents) == 1 and len(children) == 1: self.edges.add((parents[0], children[0]))
                    else: self.gap(file, "ambiguous_lock_dependency")
            if packages: self.documents.append(file)

    def npm(self, file, data):
        module = posixpath.dirname(file)
        if file.endswith("package.json"):
            for key, scope in (("dependencies", "production"), ("devDependencies", "development"), ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
                for name, value in data.get(key, {}).items():
                    version = value if isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", value) else None
                    self.add("npm", name, version, module, file, declared_range=str(value), scope=scope)
            self.documents.append(file)
        packages = data.get("packages", {})
        mapping = {}
        root = packages.get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {})) | set(root.get("optionalDependencies", {}))
        for path, package in packages.items():
            if not path or not isinstance(package, dict): continue
            name = package.get("name") or path.rsplit("node_modules/", 1)[-1]
            if not package.get("version"):
                self.gap(file, "workspace_or_link_dependency"); continue
            cid = self.add("npm", name, package["version"], module, file, relationship="direct" if path == "node_modules/" + name and name in direct else "transitive", scope="development" if package.get("dev") else "production", context=path)
            mapping[path] = cid
        for path, package in packages.items():
            if path not in mapping: continue
            for name in set(package.get("dependencies", {})) | set(package.get("optionalDependencies", {})) | set(package.get("peerDependencies", {})):
                parent = path
                while True:
                    candidate = (parent + "/" if parent else "") + "node_modules/" + name
                    if candidate in mapping:
                        self.edges.add((mapping[path], mapping[candidate])); break
                    if not parent:
                        self.gap(file, "npm_dependency_edge_unresolved"); break
                    parent = posixpath.dirname(parent)
        if packages: self.documents.append(file)
        elif file.endswith("lock.json"): self.gap(file, "npm_lock_version_not_supported")

    def sbom(self, file, data, origin="repository", module=None):
        if data.get("bomFormat") != "CycloneDX": return
        refs = {}
        for item in data.get("components", []):
            purl = item.get("purl", "")
            match = re.match(r"pkg:([^/]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$", purl)
            if not match:
                self.gap(file, "sbom_component_without_supported_identity"); continue
            kind, name, version = match.groups()
            ecosystem = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "deb": "Debian", "rpm": "RPM", "apk": "Alpine"}.get(kind, kind)
            if kind in ("deb", "apk", "rpm") and "/" in name:
                distro, name = name.split("/", 1)
                if kind == "deb" and distro == "ubuntu": ecosystem = "Ubuntu"
            if kind == "maven": name = name.replace("/", ":", 1)
            refs[item.get("bom-ref", purl)] = self.add(ecosystem, unquote(name), item.get("version") or version, posixpath.dirname(file) if module is None else module, file, origin=origin, relationship="unknown")
        root = data.get("metadata", {}).get("component", {}).get("bom-ref")
        for edge in data.get("dependencies", []):
            for child in edge.get("dependsOn", []):
                if child not in refs: continue
                if edge.get("ref") == root:
                    self.components[refs[child]]["relationship"] = "direct"
                elif edge.get("ref") in refs:
                    self.edges.add((refs[edge["ref"]], refs[child]))
        self.documents.append(file)
        if not data.get("dependencies"): self.gap(file, "sbom_graph_not_provided")

    def run(self):
        references, constraints_only, reference_modules = set(), set(), {}
        for file, text in self.files.items():
            stage_aliases, build_args = set(), {}
            for number, line in enumerate(text.splitlines(), 1):
                constraint = re.match(r"\s*(?:-c\s*|--constraint(?:=|\s+))([^\s#]+)", line)
                if constraint:
                    constraints_only.add(posixpath.normpath(posixpath.join(posixpath.dirname(file), constraint[1])))
                if len(self.events) < 500 and INSTALL.search(line):
                    self.events.append({"file": file, "line": number, "kind": "installation_or_dynamic_execution_candidate", "evidence": redact(line.strip()[:500]), "status": "candidate_not_executed"})
                for match in re.finditer(r"(?:pip3?\s+install|python\S*\s+-m\s+pip\s+install).*?(?:-r\s*|--requirement(?:=|\s+))([\w./-]+)", line):
                    reference = match[1]
                    choices = [reference, posixpath.normpath(posixpath.join(posixpath.dirname(file), reference))]
                    available = next((p for p in choices if p in self.files), None)
                    if available:
                        references.add(available)
                        reference_modules[available] = posixpath.dirname(file)
                    else: self.gap(file, f"install_reference_unresolved:line={number}")
                if PurePosixPath(file).name.lower().startswith("dockerfile"):
                    argument = re.match(r"\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line, re.I)
                    if argument: build_args[argument[1]] = argument[2]
                    match = re.match(r"\s*FROM\s+(?:--platform=(\S+)\s+)?(\S+)", line, re.I)
                    if match and match[2].lower() != "scratch" and match[2] not in stage_aliases:
                        reference = re.sub(r"\$\{?(\w+)\}?", lambda m: build_args.get(m[1], m[0]), match[2])
                        self.images.append({"file": file, "line": number, "reference": reference, "source_reference": match[2], "requested_platform": match[1] or "linux/amd64", "status": "contents_not_scanned"})
                    alias = re.match(r"\s*FROM\s+.*\s+AS\s+(\S+)\s*$", line, re.I)
                    if alias: stage_aliases.add(alias[1])
        for file in sorted(self.files):
            name = PurePosixPath(file).name
            try:
                if file in references or (file not in constraints_only and re.fullmatch(r"requirements(?:[._-][\w.-]+)?\.(?:txt|in)", name, re.I)):
                    self.requirements(file, module=reference_modules.get(file))
                elif name.endswith(".toml") or name in ("uv.lock", "poetry.lock", "Pipfile.lock"):
                    if name == "Pipfile.lock":
                        data = json.loads(self.files[file])
                        for key in ("default", "develop"):
                            for package, spec in data.get(key, {}).items(): self.requirement(package + spec.get("version", ""), file, scope="development" if key == "develop" else "production")
                        self.documents.append(file)
                    else: self.toml(file)
                elif name == "setup.cfg":
                    parser = configparser.ConfigParser(interpolation=None); parser.read_string(self.files[file])
                    for value in parser.get("options", "install_requires", fallback="").splitlines():
                        if value.strip(): self.requirement(value, file)
                    self.documents.append(file)
                elif name in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
                    self.npm(file, json.loads(self.files[file]))
                elif name.endswith(".json") and '"bomFormat"' in self.files[file][:2000]:
                    self.sbom(file, json.loads(self.files[file]))
                elif name in ("yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle", "go.mod", "Cargo.lock", "Gemfile.lock"):
                    self.gap(file, "ecosystem_parser_not_yet_supported")
                elif name == "setup.py": self.gap(file, "dynamic_setup_not_executed")
            except (ValueError, KeyError, TypeError, configparser.Error):
                self.gap(file, "manifest_parse_failed")
        self.reconcile()
        if not self.documents: self.gap("", "no_supported_dependency_manifest")
        for component in self.components.values():
            if not component["version"]: self.gap(component["evidence"][0]["file"], "dependency_version_unresolved:" + component["name"])
        return {"components": list(self.components.values()), "edges": sorted(self.edges), "installation_candidates": self.events, "images": self.images, "gaps": self.gaps, "files_scanned": len(self.files), "dependency_files": sorted(set(self.documents)), "llm": {"status": "not_configured"}}

    def reconcile(self):
        remove, replacements = set(), {}
        for cid, component in list(self.components.items()):
            lock_names = ("uv.lock", "poetry.lock", "package-lock.json", "npm-shrinkwrap.json")
            if any(e["file"].endswith(lock_names) for e in component["evidence"]): continue
            candidates = [c for c in self.components.values() if c["id"] != cid and c["id"] not in remove and (not component["version"] or any(e["file"].endswith(lock_names) for e in c["evidence"])) and c["ecosystem"] == component["ecosystem"] and c["name"] == component["name"] and c["module"] == component["module"] and c["version"] and (not component["version"] or c["version"] == component["version"])]
            if component["relationship"] == "direct" and len(candidates) == 1:
                target = candidates[0]
                if not component["version"] and component["ecosystem"] == "PyPI":
                    try:
                        spec = component["declared_range"] if component["declared_range"] != "unresolved" else ""
                        if not Requirement(component["name"] + spec).specifier.contains(target["version"], prereleases=True): continue
                    except InvalidRequirement:
                        continue
                target["relationship"] = "direct"; target["evidence"] += component["evidence"]
                remove.add(cid); replacements[cid] = target["id"]
        self.components = {k: v for k, v in self.components.items() if k not in remove}
        self.edges = {(replacements.get(a, a), replacements.get(b, b)) for a, b in self.edges}
        children = {b for _, b in self.edges}
        for cid in children:
            if self.components[cid]["relationship"] == "unknown": self.components[cid]["relationship"] = "transitive"


def redact(value):
    value = re.sub(r"(?i)(?:https?://)[^\s/@]+:[^\s/@]+@", "https://[redacted]@", value)
    value = re.sub(r"(?:sk-(?:or-v1-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})", "[redacted]", value)
    return re.sub(r"(?i)((?:api[_-]?key|token|password|secret)[\"']?\s*[=:]\s*)[^\s,;]+", r"\1[redacted]", value)


def analyze_archive(content, scan_id, subpath=""):
    files, gaps = archive_files(content, subpath)
    result = Analyzer(scan_id, files).run()
    result["gaps"] = gaps + result["gaps"]
    return result, files
