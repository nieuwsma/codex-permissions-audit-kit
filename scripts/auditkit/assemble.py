# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Build audit.json from a home directory, snapshots, and raw scanner output."""

from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from auditkit.assess import (
    build_heuristics,
    build_matrix,
    combine_recommendations,
    headline_for,
    posture_of,
)
from auditkit.parse_codex import (
    parse_config,
    parse_mdm_output,
    parse_opencode,
    parse_requirements_file,
    parse_rules_dir,
    rules_from_requirements,
)
from auditkit.parse_tools import (
    parse_access_auditor,
    parse_aisec,
    parse_codex_cli,
    parse_mcp_audit,
    tool_recommendations,
)
from auditkit.pins import PINS
from auditkit.redact import redact_bytes, redact_text
from auditkit.snapshot import compare, display_path

NOT_COVERED = [
    {
        "item": "macOS TCC and Full Disk Access",
        "reason": "The audit never prompts for Full Disk Access or any other TCC permission.",
    },
    {
        "item": "Applying fixes",
        "reason": "The runner never calls fix, lock, pin, register, push-nucleus, revoke, redact, or hook install.",
    },
    {
        "item": "Live MCP connections",
        "reason": "mcp-audit --connect is never used, so tool lists are not fetched from running servers.",
    },
    {
        "item": "auth.json contents",
        "reason": "Only size and mtime are recorded. The file is never opened.",
    },
    {
        "item": "Elevated system policy",
        "reason": "sudo is never used. An unreadable requirements file is reported as unreadable.",
    },
]


def _write_redacted(src: Path, dest: Path) -> int:
    if not src.is_file():
        return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    body, count = redact_bytes(src.read_bytes())
    dest.write_bytes(body)
    return count


def _auth_present(snapshot: dict[str, Any]) -> bool:
    for item in snapshot.get("watched", []):
        if item.get("id") == "codex-auth":
            return bool(item.get("present"))
    return False


def _requirements(report: Path, meta: dict[str, Any]) -> dict[str, Any]:
    locations = [parse_requirements_file(Path("/etc/codex/requirements.toml"))]
    mdm_step = next((step for step in meta.get("steps", []) if step.get("id") == "mdm"), None)
    if mdm_step is None or mdm_step.get("status") == "skipped":
        reason = (mdm_step or {}).get("reason") or "MDM was not queried."
        locations.append(
            {
                "id": "mdm",
                "path": "MDM com.openai.codex requirements_toml_base64",
                "status": "skipped",
                "reason": reason,
                "sha256": None,
                "summary": None,
            }
        )
    else:
        raw = report / "tmp" / "plain" / "mdm-defaults.out"
        text = ""
        if raw.exists():
            text = raw.read_text(encoding="utf-8", errors="replace")
        exit_code = mdm_step.get("exit_code")
        locations.append(parse_mdm_output(text, exit_code if isinstance(exit_code, int) else None))
    return {"locations": locations}


def _summary(checks: list[dict[str, Any]], recs: list[dict[str, Any]], local: dict[str, Any], tools: dict[str, Any]) -> dict[str, Any]:
    counts = {"ok": 0, "warn": 0, "gap": 0, "info": 0, "skipped": 0}
    for check in checks:
        status = check["status"]
        if status in counts:
            counts[status] += 1
    rec_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for rec in recs:
        if rec["priority"] in rec_counts:
            rec_counts[rec["priority"]] += 1
    ran = []
    skipped = []
    for key, tool in tools.items():
        status = tool.get("status")
        label = tool.get("name") or key
        if status == "ok":
            ran.append(label)
        elif status == "skipped":
            skipped.append(label)
    risky_rules = sum(1 for entry in local["rules"]["entries"] if entry.get("risk") == "gap")
    return {
        "posture": posture_of(checks),
        "headline": headline_for(checks),
        "counts": counts,
        "recommendation_counts": rec_counts,
        "mcp_server_count": len(local["config"].get("mcp_servers") or []),
        "risky_allow_rule_count": risky_rules,
        "tools_ran": ran,
        "tools_skipped": skipped,
    }


def assemble(
    home: Path,
    codex_home: Path,
    xdg_config: Path,
    report: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    meta: dict[str, Any],
) -> dict[str, Any]:
    home = home.resolve()
    report.mkdir(parents=True, exist_ok=True)
    raw = report / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    replacements = int(meta.get("redaction_replacements") or 0)
    replacements += _write_redacted(codex_home / "config.toml", raw / "codex-config.redacted.toml")
    rules_root = codex_home / "rules"
    if rules_root.is_dir():
        for path in sorted(item for item in rules_root.rglob("*") if item.is_file() and not item.is_symlink()):
            rel = path.relative_to(rules_root)
            replacements += _write_redacted(path, raw / "rules" / rel)
    opencode_path = xdg_config / "opencode" / "opencode.json"
    replacements += _write_redacted(opencode_path, raw / "opencode.redacted.json")

    config = parse_config(codex_home / "config.toml", home)
    rules = parse_rules_dir(rules_root)
    rules["directory"] = display_path(rules_root, home)
    requirements = _requirements(report, meta)
    for location in requirements["locations"]:
        summary = location.get("summary") or {}
        rules["entries"].extend(rules_from_requirements(summary, location["path"]))
    opencode = parse_opencode(opencode_path, home)
    local = {
        "config": config,
        "rules": rules,
        "requirements": requirements,
        "opencode": opencode,
    }
    local_step = next((step for step in meta.get("steps", []) if step.get("id") == "local-audit"), None)
    tools = {
        "local_audit": {
            "name": "local-audit.sh",
            "status": (local_step or {}).get("status", "skipped"),
            "reason": (local_step or {}).get("reason") or "",
            "exit_code": (local_step or {}).get("exit_code"),
            "raw": (local_step or {}).get("raw") or [],
        },
        "codex_cli": parse_codex_cli(report, meta),
        "mcp_audit": parse_mcp_audit(report, meta),
        "access_auditor": parse_access_auditor(report, meta),
        "aisec_codex_audit": parse_aisec(report, meta),
    }
    checks, matrix_recs = build_matrix(local)
    heuristics = build_heuristics(local, _auth_present(before))
    recommendations = combine_recommendations(
        matrix_recs,
        heuristics,
        tool_recommendations(
            tools["mcp_audit"],
            tools["access_auditor"],
            tools["aisec_codex_audit"],
        ),
    )
    skipped = []
    for step in meta.get("steps", []):
        if step.get("status") == "skipped":
            skipped.append({"step": step.get("id"), "reason": step.get("reason") or ""})
    for check in checks:
        if check["status"] == "skipped":
            skipped.append({"step": check["id"], "reason": check["observed"]})

    verification = compare(before, after)
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": meta.get("generated_at") or "",
        "host": {
            "hostname": meta.get("hostname") or platform.node(),
            "os": platform.system().lower(),
            "platform": platform.platform(),
        },
        "kit": {"name": "codex-permissions-audit-kit", "pins": dict(PINS)},
        "invocation": {
            "flags": meta.get("flags") or {},
            "yq_patched": bool(meta.get("yq_patched")),
        },
        "summary": _summary(checks, recommendations, local, tools),
        "codex": {
            "cli": tools["codex_cli"],
            "config_path": config["config_path"],
            "config_present": config["config_present"],
            "parse_error": config["parse_error"],
            "posture": config["posture"],
            "trusted_projects": config["projects"],
            "mcp_servers": config["mcp_servers"],
            "plugins": config["plugins"],
            "features": config["features"],
            "otel": config["otel"],
        },
        "rules": rules,
        "requirements": requirements,
        "opencode": opencode,
        "tools": tools,
        "matrix": checks,
        "recommendations": recommendations,
        "skipped": skipped,
        "not_covered": NOT_COVERED,
        "verification": verification,
        "redaction": {"applied": True, "replacements": replacements},
    }
    encoded = json.dumps(document, indent=2, ensure_ascii=False)
    cleaned, extra = redact_text(encoded)
    if extra:
        document = json.loads(cleaned)
        document["redaction"]["replacements"] = replacements + extra
    return document


def dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
