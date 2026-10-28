"""Bounded HTTPS repository downloads. No git hooks or repository code execute here."""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import hashlib
from urllib.parse import quote, urljoin, urlsplit, urlunsplit


class RepositoryError(ValueError):
    pass


def repository_url(value, provider=None):
    parsed = urlsplit(str(value).strip())
    host = (parsed.hostname or "").lower()
    allowed = {"github.com", "gitlab.com"} | set(filter(None, os.getenv("SCA_REPOSITORY_GITLAB_HOSTS", "").split(",")))
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.query or parsed.fragment or host not in allowed:
        raise RepositoryError("GitHub/GitLab의 HTTPS 저장소 주소를 입력해 주세요. 자체 GitLab 호스트는 관리자가 등록해야 합니다.")
    namespace = parsed.path.strip("/").removesuffix(".git")
    parts = namespace.split("/")
    kind = "github" if host == "github.com" else "gitlab"
    if (provider and provider != kind) or len(parts) < 2 or (kind == "github" and len(parts) != 2) or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", p) or p in (".", "..") for p in parts):
        raise RepositoryError("저장소 경로 또는 제공자가 올바르지 않습니다.")
    return {"provider": kind, "host": host, "namespace": namespace, "url": f"https://{host}/{namespace}"}


def public_addresses(host, port=443, allow_private=False):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    def denied(address):
        value = ipaddress.ip_address(address)
        return not value.is_global and not (allow_private and value.is_private and not value.is_loopback and not value.is_link_local and not value.is_reserved and not value.is_multicast and not value.is_unspecified)
    if not addresses or any(denied(a[4][0]) for a in addresses):
        raise RepositoryError("내부·예약 네트워크 주소에는 연결할 수 없습니다.")
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        private_hosts = set(filter(None, os.getenv("SCA_REPOSITORY_PRIVATE_GITLAB_HOSTS", "").split(",")))
        addresses = public_addresses(self.host, self.port, allow_private=self.host in private_hosts)
        last = None
        for family, kind, proto, _, address in addresses:
            raw = socket.socket(family, kind, proto)
            raw.settimeout(self.timeout)
            try:
                raw.connect(address)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except OSError as exc:
                raw.close()
                last = exc
        raise RepositoryError("저장소 서버에 연결하지 못했습니다.") from last


def https_get(url, allowed_hosts, headers=None, maximum=64 * 1024 * 1024):
    original_host = urlsplit(url).hostname
    for _ in range(5):
        p = urlsplit(url)
        if p.scheme != "https" or p.hostname not in allowed_hosts or p.port not in (None, 443) or p.username or p.password:
            raise RepositoryError("허용되지 않은 다운로드 목적지입니다.")
        safe_headers = {"User-Agent": "SCA-Monitor-Repository/1.0", "Accept": "application/json"}
        if p.hostname == original_host:
            safe_headers.update(headers or {})
        conn = PinnedHTTPS(p.hostname, timeout=30, context=ssl.create_default_context())
        try:
            conn.request("GET", urlunsplit(("", "", p.path or "/", p.query, "")), headers=safe_headers)
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                url = urljoin(url, response.getheader("Location", ""))
                continue
            if response.status != 200:
                raise RepositoryError(f"저장소 조회 실패 (HTTP {response.status}). 주소·읽기 권한을 확인해 주세요.")
            length = response.getheader("Content-Length")
            if length and int(length) > maximum:
                raise RepositoryError("분석 가능한 다운로드 크기를 초과했습니다.")
            chunks, size = [], 0
            while True:
                chunk = response.read(min(65536, maximum + 1 - size))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise RepositoryError("분석 가능한 다운로드 크기를 초과했습니다.")
        finally:
            conn.close()
    raise RepositoryError("저장소 다운로드 리다이렉트가 너무 많습니다.")


def fetch_repository(snapshot, secret=None, commit=None):
    host, namespace = snapshot["host"], snapshot["namespace"]
    ref = quote(commit or snapshot["ref"], safe="")
    headers = {"Authorization": "Bearer " + secret["secret"]} if secret else {}
    if snapshot["provider"] == "github":
        root = "https://api.github.com/repos/" + namespace
        document = json.loads(https_get(root + "/commits/" + (ref if ref != "HEAD" else "HEAD"), {"api.github.com"}, headers, maximum=2_000_000))
        sha = document["sha"]
        archive_url = root + "/tarball/" + sha
        allowed = {"api.github.com", "codeload.github.com"}
    else:
        root = f"https://{host}/api/v4/projects/{quote(namespace, safe='')}/repository"
        document = json.loads(https_get(root + "/commits/" + ref, {host}, headers, maximum=2_000_000))
        sha = document["id"]
        archive_url = root + "/archive.tar.gz?sha=" + sha
        allowed = {host}
    if not re.fullmatch(r"[0-9a-f]{40,64}", sha) or (commit and sha != commit):
        raise RepositoryError("고정된 저장소 commit을 확인하지 못했습니다.")
    return sha, https_get(archive_url, allowed, headers)


def resolve_dockerhub_image(reference):
    """Pin public Docker Hub images without executing or loading them into Docker."""
    value = reference.removeprefix("docker.io/").removeprefix("index.docker.io/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", value): raise RepositoryError("이미지 참조를 해석하지 못했습니다.")
    if "/" in value and ("." in value.split("/", 1)[0] or ":" in value.split("/", 1)[0]): raise RepositoryError("현재 1차 digest 조회는 공개 Docker Hub 이미지를 지원합니다.")
    if "@" in value: name, tag = value.split("@", 1)
    elif ":" in value: name, tag = value.rsplit(":", 1)
    else: name, tag = value, "latest"
    if "/" not in name: name = "library/" + name
    token = json.loads(https_get("https://auth.docker.io/token?service=registry.docker.io&scope=" + quote("repository:" + name + ":pull", safe=""), {"auth.docker.io"}, maximum=100000))["token"]
    raw = https_get(f"https://registry-1.docker.io/v2/{name}/manifests/{quote(tag, safe=':')}", {"registry-1.docker.io"}, {"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}, maximum=2000000)
    manifest = json.loads(raw)
    if manifest.get("manifests"):
        matching = [item for item in manifest["manifests"] if item.get("platform", {}).get("architecture") == "amd64" and item.get("platform", {}).get("os") == "linux"]
        if not matching: raise RepositoryError("linux/amd64 이미지가 없습니다.")
        digest = matching[0]["digest"]
    else: digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest): raise RepositoryError("이미지 digest를 검증하지 못했습니다.")
    return {"resolved": "docker.io/" + name + "@" + digest, "digest": digest, "platform": "linux/amd64", "status": "digest_pinned_contents_not_scanned"}
