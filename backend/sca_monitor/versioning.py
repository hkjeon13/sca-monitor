from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Any


def version_is_affected(version: str, affected_versions: list[str], affected_ranges: list[dict[str, Any]]) -> bool:
    if version in set(affected_versions):
        return True
    for range_item in affected_ranges:
        if range_contains_version(version, range_item):
            return True
    return False


def range_contains_version(version: str, range_item: dict[str, Any]) -> bool:
    events = range_item.get("events") or []
    introduced: str | None = None
    for event in events:
        if "introduced" in event:
            introduced = str(event["introduced"])
            continue
        if "fixed" in event:
            fixed = str(event["fixed"])
            if introduced is not None and version_gte(version, introduced) and version_lt(version, fixed):
                return True
            introduced = None
            continue
        if "last_affected" in event:
            last_affected = str(event["last_affected"])
            if introduced is not None and version_gte(version, introduced) and version_lte(version, last_affected):
                return True
            continue
        if "limit" in event:
            limit = str(event["limit"])
            if introduced is not None and version_gte(version, introduced) and version_lt(version, limit):
                return True
            introduced = None
    return introduced is not None and version_gte(version, introduced)


def version_gte(left: str, right: str) -> bool:
    return compare_versions(left, right) >= 0


def version_lte(left: str, right: str) -> bool:
    return compare_versions(left, right) <= 0


def version_lt(left: str, right: str) -> bool:
    return compare_versions(left, right) < 0


def compare_versions(left: str, right: str) -> int:
    left_parts = version_parts(left)
    right_parts = version_parts(right)
    max_len = max(len(left_parts), len(right_parts))
    for idx in range(max_len):
        left_part = left_parts[idx] if idx < len(left_parts) else 0
        right_part = right_parts[idx] if idx < len(right_parts) else 0
        if left_part == right_part:
            continue
        if isinstance(left_part, int) and isinstance(right_part, int):
            return -1 if left_part < right_part else 1
        if isinstance(left_part, int):
            return 1
        if isinstance(right_part, int):
            return -1
        return -1 if left_part < right_part else 1
    return 0


def version_parts(version: str) -> list[int | str]:
    cleaned = version.strip().lstrip("v")
    parts: list[int | str] = []
    for token in re.split(r"[.+_~:-]", cleaned):
        if token == "":
            continue
        if token.isdigit():
            parts.append(int(token))
            continue
        for chunk in re.findall(r"\d+|[A-Za-z]+", token):
            parts.append(int(chunk) if chunk.isdigit() else chunk.lower())
    return parts or [0]


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(compare_versions))
