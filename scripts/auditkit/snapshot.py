# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Hash or stat the files the audit must not modify.

auth.json is never opened. Only its size and mtime are recorded.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any


def display_path(path: Path, home: Path) -> str:
    try:
        rel = path.resolve().relative_to(home.resolve())
    except (OSError, ValueError):
        return str(path)
    text = rel.as_posix()
    return "~" if text == "." else "~/" + text


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_record(path: Path, home: Path, kind: str) -> dict[str, Any]:
    shown = display_path(path, home)
    if kind == "size_mtime":
        record: dict[str, Any] = {
            "id": "codex-auth",
            "path": shown,
            "kind": "size_mtime",
            "content_read": False,
        }
        try:
            st = path.stat()
        except OSError as exc:
            record.update({"present": False, "size": None, "mtime_ns": None, "error": str(exc)})
            return record
        record.update({"present": True, "size": st.st_size, "mtime_ns": st.st_mtime_ns, "error": None})
        return record

    record = {"path": shown, "kind": "sha256", "content_read": False}
    if not path.exists():
        record.update({"present": False, "sha256": None, "error": None})
        return record
    try:
        record.update({"present": True, "sha256": _sha256(path), "error": None, "content_read": True})
    except OSError as exc:
        record.update({"present": True, "sha256": None, "error": str(exc)})
    return record


def _rules_record(root: Path, home: Path) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": "codex-rules",
        "path": display_path(root, home),
        "kind": "tree",
        "content_read": True,
        "files": {},
        "error": None,
    }
    if not root.exists():
        record["present"] = False
        return record
    record["present"] = True
    files: dict[str, str] = {}
    try:
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                files[path.relative_to(root).as_posix()] = "symlink:" + os.readlink(path)
                continue
            if path.is_file():
                files[path.relative_to(root).as_posix()] = _sha256(path)
    except OSError as exc:
        record["error"] = str(exc)
    record["files"] = files
    return record


def snapshot(home: Path, codex_home: Path, xdg_config: Path) -> dict[str, Any]:
    """Record hashes and auth.json size/mtime. Does not open auth.json."""
    home = home.resolve()
    opencode = xdg_config / "opencode" / "opencode.json"
    watched = [
        _file_record(codex_home / "config.toml", home, "sha256") | {"id": "codex-config"},
        _rules_record(codex_home / "rules", home),
        _file_record(opencode, home, "sha256") | {"id": "opencode"},
        _file_record(codex_home / "auth.json", home, "size_mtime"),
        _file_record(codex_home / "hooks.json", home, "sha256") | {"id": "codex-hooks"},
    ]
    return {"watched": watched}


def _changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    fields = ("present", "sha256", "files", "size", "mtime_ns", "error")
    return any(before.get(field) != after.get(field) for field in fields)


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_by_id = {item["id"]: item for item in before.get("watched", [])}
    after_by_id = {item["id"]: item for item in after.get("watched", [])}
    ids = list(dict.fromkeys([*before_by_id.keys(), *after_by_id.keys()]))
    watched = []
    for item_id in ids:
        left = before_by_id.get(item_id, {})
        right = after_by_id.get(item_id, {})
        changed = _changed(left, right)
        watched.append(
            {
                "id": item_id,
                "path": right.get("path") or left.get("path"),
                "kind": right.get("kind") or left.get("kind"),
                "content_read": bool((right or left).get("content_read")),
                "before": _public_side(left),
                "after": _public_side(right),
                "changed": changed,
            }
        )
    ok = not any(item["changed"] for item in watched)
    notes = [
        "auth.json was not opened. Only its size and mtime were compared.",
        "Watched files were recorded before any scanner ran and compared again after.",
    ]
    if not ok:
        notes.append("A watched file changed while the audit was running.")
    return {"ok": ok, "watched": watched, "notes": notes}


def _public_side(record: dict[str, Any]) -> dict[str, Any]:
    if not record:
        return {"present": False}
    side: dict[str, Any] = {"present": record.get("present")}
    if record.get("kind") == "size_mtime":
        side["size"] = record.get("size")
        side["mtime_ns"] = record.get("mtime_ns")
    elif record.get("kind") == "tree":
        side["files"] = record.get("files") or {}
    else:
        side["sha256"] = record.get("sha256")
    if record.get("error"):
        side["error"] = record["error"]
    return side
