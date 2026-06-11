from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlparse

from .migrations import (
    MINIMUM_SUPPORTED_MIGRATION_VERSION,
    REQUIRED_MIGRATION_VERSION,
    migration_files,
    migration_version,
)


BEGIN_RE = re.compile(r"^BEGIN(?:\s+IMMEDIATE)?\s*;?$", re.IGNORECASE)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def postgres_sql(sql: str) -> str:
    if BEGIN_RE.match(sql.strip()):
        return "-- transaction already managed by psycopg adapter"

    converted: list[str] = []
    in_single_quote = False
    in_double_quote = False
    index = 0
    while index < len(sql):
        char = sql[index]
        if char == "'" and not in_double_quote:
            converted.append(char)
            if in_single_quote and index + 1 < len(sql) and sql[index + 1] == "'":
                converted.append(sql[index + 1])
                index += 2
                continue
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote:
            converted.append(char)
            in_double_quote = not in_double_quote
        elif char == "?" and not in_single_quote and not in_double_quote:
            converted.append("%s")
        else:
            converted.append(char)
        index += 1
    return "".join(converted)


class PostgresCursorAdapter:
    def __init__(self, cursor):
        self.cursor = cursor

    @property
    def rowcount(self) -> int:
        return self.cursor.rowcount

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class PostgresConnectionAdapter:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql: str, params: tuple | list | None = None) -> PostgresCursorAdapter:
        translated = postgres_sql(sql)
        cursor = self.conn.execute(translated, params or ())
        return PostgresCursorAdapter(cursor)

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()


class Database:
    def __init__(self, database_url_or_path: str | Path):
        self.database_url = self._normalize_database_url(database_url_or_path)
        parsed = urlparse(self.database_url)
        self.backend = "sqlite" if parsed.scheme == "sqlite" else parsed.scheme
        if self.backend == "sqlite":
            self.path = self._sqlite_path(parsed)
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif self.backend in ("postgres", "postgresql"):
            self.backend = "postgres"
            self.path = None
        else:
            raise ValueError(f"unsupported database backend: {self.backend}")

    @staticmethod
    def _normalize_database_url(database_url_or_path: str | Path) -> str:
        if isinstance(database_url_or_path, Path):
            return f"sqlite:///{database_url_or_path.resolve()}"
        value = str(database_url_or_path)
        if "://" not in value:
            return f"sqlite:///{Path(value).resolve()}"
        return value

    @staticmethod
    def _sqlite_path(parsed) -> Path:
        if parsed.netloc:
            path = Path(f"//{parsed.netloc}{unquote(parsed.path)}")
        else:
            path = Path(unquote(parsed.path))
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()

    @contextmanager
    def connect(self) -> Iterator[Any]:
        if self.backend == "postgres":
            with self._connect_postgres() as conn:
                yield conn
            return
        assert self.path is not None
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _connect_postgres(self) -> Iterator["PostgresConnectionAdapter"]:
        try:
            import psycopg  # type: ignore[import-not-found]
            from psycopg.rows import dict_row  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psycopg is required to use the PostgreSQL runtime query adapter") from exc

        conn = psycopg.connect(self.database_url, row_factory=dict_row)
        adapter = PostgresConnectionAdapter(conn)
        try:
            yield adapter
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def migrate(self) -> None:
        if self.backend == "postgres":
            self._migrate_postgres()
            return
        with self.connect() as conn:
            current = self.current_migration_version(conn)
            for path in migration_files("sqlite"):
                version = migration_version(path)
                if version <= current:
                    continue
                conn.executescript(path.read_text(encoding="utf-8"))
                conn.execute(
                    """
                    INSERT OR IGNORE INTO schema_migrations (version, name, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (version, path.stem, utcnow()),
                )
            self._seed_advisories(conn)

    def _migrate_postgres(self) -> None:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psycopg is required to run PostgreSQL migrations") from exc

        with psycopg.connect(self.database_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """
                )
                cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                current = cur.fetchone()[0]
                for path in migration_files("postgres"):
                    version = migration_version(path)
                    if version <= current:
                        continue
                    cur.execute(path.read_text(encoding="utf-8"))
                    cur.execute(
                        """
                        INSERT INTO schema_migrations (version, name)
                        VALUES (%s, %s)
                        ON CONFLICT (version) DO NOTHING
                        """,
                        (version, path.stem),
                    )
            conn.commit()

    def current_migration_version(self, conn: sqlite3.Connection | None = None) -> int:
        if self.backend == "postgres":
            return self._current_postgres_migration_version()

        def read(connection: sqlite3.Connection) -> int:
            try:
                row = connection.execute("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations").fetchone()
            except sqlite3.OperationalError:
                return 0
            return int(row["version"] if isinstance(row, sqlite3.Row) else row[0])

        if conn is not None:
            return read(conn)
        with self.connect() as connection:
            return read(connection)

    def _current_postgres_migration_version(self) -> int:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("psycopg is required to read PostgreSQL migration status") from exc

        with psycopg.connect(self.database_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                return int(cur.fetchone()[0])

    def readiness(self) -> dict[str, Any]:
        current = self.current_migration_version()
        compatible = current >= MINIMUM_SUPPORTED_MIGRATION_VERSION
        return {
            "database": "ok" if compatible else "migration_too_old",
            "database_backend": self.backend,
            "migration": {
                "current": current,
                "required": REQUIRED_MIGRATION_VERSION,
                "minimum_supported": MINIMUM_SUPPORTED_MIGRATION_VERSION,
                "compatible": compatible,
            },
        }

    def _seed_advisories(self, conn: sqlite3.Connection) -> None:
        seeds = [
            {
                "advisory_id": "DEMO-OSV-LODASH-41720",
                "source": "OSV",
                "summary": "Demo advisory for lodash versions up to 4.17.20",
                "severity": "high",
                "ecosystem": "npm",
                "package_name": "lodash",
                "affected_versions": ["4.17.20", "4.17.19"],
                "fixed_version": "4.17.21",
                "is_known_exploited": False,
                "is_malicious_package": False,
            },
            {
                "advisory_id": "DEMO-MAL-EVENT-STREAM",
                "source": "OpenSSF",
                "summary": "Demo malicious package advisory for event-stream 3.3.6",
                "severity": "critical",
                "ecosystem": "npm",
                "package_name": "event-stream",
                "affected_versions": ["3.3.6"],
                "fixed_version": None,
                "is_known_exploited": False,
                "is_malicious_package": True,
            },
        ]
        for item in seeds:
            existing = conn.execute(
                "SELECT id FROM advisories WHERE advisory_id = ?", (item["advisory_id"],)
            ).fetchone()
            if existing:
                continue
            conn.execute(
                """
                INSERT INTO advisories (
                    id, advisory_id, source, summary, severity, ecosystem, package_name,
                    canonical_package_name, affected_versions, fixed_version,
                    is_known_exploited, is_malicious_package, published_at, modified_at, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    item["advisory_id"],
                    item["source"],
                    item["summary"],
                    item["severity"],
                    item["ecosystem"],
                    item["package_name"],
                    canonical_package_name(item["ecosystem"], item["package_name"]),
                    json.dumps(item["affected_versions"]),
                    item["fixed_version"],
                    int(item["is_known_exploited"]),
                    int(item["is_malicious_package"]),
                    utcnow(),
                    utcnow(),
                    json.dumps(item),
                ),
            )


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def json_column(value: Any, default: Any):
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return default
    return value


def canonical_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "pypi":
        return name.lower().replace("_", "-").replace(".", "-")
    if ecosystem.lower() == "maven":
        return name.lower()
    return name.lower()
