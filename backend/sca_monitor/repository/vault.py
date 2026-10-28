"""Authenticated encryption with a server key kept outside the database."""
import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Vault:
    def __init__(self, data_dir):
        self.path = Path(os.getenv("SCA_REPOSITORY_KEY_FILE", str(data_dir / "repository-credentials.key")))

    def key(self, create=False):
        if create and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as target:
                    target.write(os.urandom(32)); target.flush(); os.fsync(target.fileno())
        if not self.path.is_file() or self.path.stat().st_mode & 0o077:
            raise ValueError("자격 증명 암호화 키가 없거나 파일 권한이 안전하지 않습니다.")
        key = self.path.read_bytes()
        if len(key) != 32:
            raise ValueError("자격 증명 암호화 키 형식이 올바르지 않습니다.")
        return key

    def encrypt(self, value, context):
        key, nonce = self.key(create=True), os.urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, json.dumps(value).encode(), context.encode())
        return base64.urlsafe_b64encode(nonce + encrypted).decode(), hashlib.sha256(key).hexdigest()[:16]

    def decrypt(self, value, context):
        payload = base64.urlsafe_b64decode(value)
        return json.loads(AESGCM(self.key()).decrypt(payload[:12], payload[12:], context.encode()))
