# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Normalize third-party scanner output into findings and recommendations."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from auditkit.pins import PINS
from auditkit.redact import redact_obj, redact_text

_MAX_FINDINGS = 100
_SECRET_LINE = re.compile(
    r"^(?P<types>.+?):\s*(?P<preview>.+?)\s+·\s+last used\s+(?P<date>.+?)\s+·\s+(?P<path>\S+)\s*$"
)
_FINDING_LINE = re.compile(
    r"^\[(?P<risk>[A-Z]+)\s*\]\s+(?P<agent>.+?)\s+·\s+(?P<category>.+?)\s+·\s+(?P<title>.+?)\s*$"
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_json(path: Path) -> Any:
    text = _read(path)
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _clip(text: str, limit: int = 500) -> str:
    redacted, _ = redact_text(text or "")
    redacted = redacted.strip()
    if len(redacted) <= limit:
        return redacted
    return redacted[: limit - 1].rstrip() + "…"


def _step(meta: dict[str, Any], step_id: str) -> dict[str, Any]:
    for step in meta.get("steps", []):
        if step.get("id") == step_id:
            return step
    return {"id": step_id, "status": "skipped", "reason": "The runner did not record this step.", "raw": []}


def _priority(severity: str) -> str | None:
    lowered = severity.lower()
    if lowered in {"critical"}:
        return "critical"
    if lowered in {"high", "fail"}:
        return "high"
    if lowered in {"medium", "warn", "warning"}:
        return "medium"
    return None


def parse_mcp_audit(report: Path, meta: dict[str, Any]) -> dict[str, Any]:
    step = _step(meta, "mcp-audit")
    result: dict[str, Any] = {
        "name": "mcp-audit",
        "status": step.get("status", "skipped"),
        "reason": step.get("reason") or "",
        "version_pin": PINS["MCP_AUDIT_VERSION"],
        "version_observed": None,
        "grade": None,
        "score": None,
        "discover_clients": [],
        "reach": [],
        "findings": [],
        "recommendations": [],
        "raw": step.get("raw") or [],
    }
    if result["status"] != "ok":
        return result
    version_text = _read(report / "raw" / "mcp-version.out")
    match = re.search(r"(\d+\.\d+\.\d+)", version_text)
    if match:
        result["version_observed"] = match.group(1)
    discover = _load_json(report / "raw" / "mcp-discover.out")
    if isinstance(discover, list):
        clients = []
        for item in discover:
            if isinstance(item, dict) and item.get("client"):
                clients.append({"client": str(item.get("client")), "path": _clip(str(item.get("path") or ""), 180)})
        result["discover_clients"] = clients[:_MAX_FINDINGS]
    scan = _load_json(report / "raw" / "mcp-scan.out")
    if not isinstance(scan, dict):
        scan = _load_json(report / "raw" / "mcp-check.out")
    if isinstance(scan, dict):
        cleaned, _ = redact_obj(scan)
        if isinstance(cleaned, dict):
            scan = cleaned
        if not result["version_observed"] and isinstance(scan.get("version"), str):
            result["version_observed"] = scan["version"]
        score = scan.get("score") if isinstance(scan.get("score"), dict) else {}
        result["grade"] = score.get("grade")
        result["score"] = score.get("numeric")
        findings = []
        for item in scan.get("findings") or []:
            if not isinstance(item, dict):
                continue
            findings.append(
                {
                    "id": str(item.get("id") or ""),
                    "severity": str(item.get("severity") or ""),
                    "title": _clip(str(item.get("title") or ""), 180),
                    "detail": _clip(str(item.get("description") or "")),
                    "server": str(item.get("server") or ""),
                    "remediation": _clip(str(item.get("remediation") or "")),
                    "path": _clip(str(item.get("finding_path") or ""), 240),
                }
            )
            if len(findings) >= _MAX_FINDINGS:
                break
        result["findings"] = findings
        result["recommendations"] = _mcp_recommendations(findings)
    reach = _load_json(report / "raw" / "mcp-reach.out")
    if isinstance(reach, dict):
        cards = []
        for agent in reach.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            reasons = []
            for reason in agent.get("reasons") or []:
                if isinstance(reason, dict):
                    reasons.append(_clip(str(reason.get("text") or ""), 300))
                elif isinstance(reason, str):
                    reasons.append(_clip(reason, 300))
            cards.append(
                {
                    "name": str(agent.get("name") or agent.get("id") or ""),
                    "verdict": str(agent.get("verdict") or ""),
                    "reasons": [item for item in reasons if item][:8],
                }
            )
        result["reach"] = cards
        result["recommendations"].extend(_reach_recommendations(cards, len(result["recommendations"])))
    return result


def _mcp_recommendations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recs = []
    for index, finding in enumerate(findings):
        priority = _priority(finding.get("severity") or "")
        if not priority:
            continue
        ident = finding.get("id") or str(index + 1)
        recs.append(
            {
                "id": f"TOOL-MCP-{ident}",
                "priority": priority,
                "source": "tool",
                "tool": "mcp-audit",
                "title": finding.get("title") or "mcp-audit finding",
                "detail": finding.get("remediation") or finding.get("detail") or "",
                "rule_id": f"TOOL-MCP-{ident}",
            }
        )
    return recs


def _reach_recommendations(cards: list[dict[str, Any]], start: int) -> list[dict[str, Any]]:
    recs = []
    for card in cards:
        verdict = card.get("verdict") or ""
        if verdict not in {"not_safe_to_allow", "needs_work"}:
            continue
        priority = "high" if verdict == "not_safe_to_allow" else "medium"
        reason = "; ".join(card.get("reasons") or []) or verdict
        recs.append(
            {
                "id": f"TOOL-MCP-REACH-{card.get('name') or start}",
                "priority": priority,
                "source": "tool",
                "tool": "mcp-audit",
                "title": f"{card.get('name') or 'Agent'} reach verdict: {verdict}",
                "detail": reason,
                "rule_id": f"TOOL-MCP-REACH-{card.get('name') or start}",
            }
        )
    return recs


def parse_access_auditor(report: Path, meta: dict[str, Any]) -> dict[str, Any]:
    step = _step(meta, "access-auditor")
    result: dict[str, Any] = {
        "name": "AI Access Auditor",
        "status": step.get("status", "skipped"),
        "reason": step.get("reason") or "",
        "commit_pin": PINS["ACCESS_AUDITOR_COMMIT"],
        "commit_observed": meta.get("access_auditor_commit") or None,
        "findings": [],
        "recommendations": [],
        "tcc_readable": None,
        "grant_count": None,
        "raw": step.get("raw") or [],
    }
    if result["status"] != "ok":
        return result
    text, _ = redact_text(_read(report / "raw" / "access-auditor.out"))
    findings = _parse_access_text(text)
    result["findings"] = findings
    footer = re.search(r"(\d+)\s+grants found\.\s+TCC readable:\s+(yes|no)", text)
    if footer:
        result["grant_count"] = int(footer.group(1))
        result["tcc_readable"] = footer.group(2) == "yes"
    result["recommendations"] = _access_recommendations(findings)
    return result


def _parse_access_text(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    findings = []
    index = 0
    while index < len(lines):
        match = _FINDING_LINE.match(lines[index].rstrip())
        if not match:
            index += 1
            continue
        detail = ""
        if index + 1 < len(lines) and lines[index + 1].startswith((" ", "\t")):
            detail = lines[index + 1].strip()
            index += 1
        category = match.group("category").strip()
        finding: dict[str, Any] = {
            "risk": match.group("risk").lower(),
            "agent": match.group("agent").strip(),
            "category": category,
            "title": _clip(match.group("title").strip(), 200),
            "path": "",
            "detail": "",
            "secret": None,
        }
        if "secret" in category.lower():
            secret = _secret_from_detail(detail, finding["title"])
            finding["secret"] = secret
            finding["path"] = secret.get("path") or ""
        else:
            finding["detail"] = _clip(detail)
            path_match = re.search(r"(~/\S+|/\S+)", detail)
            if path_match:
                finding["path"] = path_match.group(1).rstrip(".,)")
        findings.append(finding)
        if len(findings) >= _MAX_FINDINGS:
            break
        index += 1
    return findings


def _secret_from_detail(detail: str, title: str) -> dict[str, str]:
    match = _SECRET_LINE.match(detail.strip())
    if match:
        preview, _ = redact_text(match.group("preview"))
        if len(preview) > 24:
            preview = preview[:8] + "…"
        return {
            "type": match.group("types").strip(),
            "date": match.group("date").strip(),
            "preview": preview,
            "path": match.group("path").strip(),
        }
    path_match = re.search(r"(~/\S+|/\S+)", detail)
    return {
        "type": title,
        "date": "",
        "preview": "[REDACTED]",
        "path": path_match.group(1).rstrip(".,)") if path_match else "",
    }


def _access_recommendations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recs = []
    for index, finding in enumerate(findings, start=1):
        priority = _priority(finding.get("risk") or "")
        if priority is None and finding.get("secret"):
            priority = "high"
        if not priority:
            continue
        if finding.get("secret"):
            secret = finding["secret"]
            detail = (
                f"Rotate the {secret.get('type') or 'credential'} found in "
                f"{secret.get('path') or 'a session log'}. "
                "The report keeps only the path, type, date, and a masked preview."
            )
            if secret.get("date"):
                detail += f" Last used {secret['date']}."
        else:
            detail = finding.get("detail") or finding.get("title") or ""
        recs.append(
            {
                "id": f"TOOL-ACCESS-{index}",
                "priority": priority,
                "source": "tool",
                "tool": "ai-access-auditor",
                "title": finding.get("title") or "AI Access Auditor finding",
                "detail": detail,
                "rule_id": f"TOOL-ACCESS-{index}",
            }
        )
    return recs


def parse_aisec(report: Path, meta: dict[str, Any]) -> dict[str, Any]:
    step = _step(meta, "aisec-codex-audit")
    result: dict[str, Any] = {
        "name": "Codex Security Audit",
        "status": step.get("status", "skipped"),
        "reason": step.get("reason") or "",
        "commit_pin": PINS["AISEC_COMMIT"],
        "commit_observed": meta.get("aisec_commit") or None,
        "summary": {"pass": 0, "warn": 0, "fail": 0, "info": 0},
        "checks": [],
        "recommendations": [],
        "yq_patched": bool(meta.get("yq_patched")),
        "raw": step.get("raw") or [],
    }
    if result["status"] != "ok":
        return result
    document = _load_json(report / "raw" / "aisec.json")
    if not isinstance(document, dict):
        result["status"] = "error"
        result["reason"] = "The JSON report was missing or not an object."
        return result
    cleaned, _ = redact_obj(document)
    if isinstance(cleaned, dict):
        document = cleaned
    summary = document.get("summary") if isinstance(document.get("summary"), dict) else {}
    result["summary"] = {
        "pass": int(summary.get("pass") or 0),
        "warn": int(summary.get("warn") or 0),
        "fail": int(summary.get("fail") or 0),
        "info": int(summary.get("info") or 0),
    }
    checks = []
    recs = []
    for item in document.get("checks") or []:
        if not isinstance(item, dict):
            continue
        check = {
            "id": str(item.get("id") or ""),
            "status": str(item.get("status") or ""),
            "title": _clip(str(item.get("title") or ""), 200),
            "detail": _clip(str(item.get("detail") or "")),
            "why": _clip(str(item.get("why") or "")),
            "guide_step": item.get("guide_step"),
        }
        checks.append(check)
        status = check["status"].upper()
        if status not in {"FAIL", "WARN"}:
            continue
        ident = check["id"] or str(len(recs) + 1)
        recs.append(
            {
                "id": f"TOOL-AISEC-{ident}",
                "priority": "high" if status == "FAIL" else "medium",
                "source": "tool",
                "tool": "aisec-codex-audit",
                "title": check["title"] or "Codex Security Audit finding",
                "detail": check["why"] or check["detail"],
                "rule_id": f"TOOL-AISEC-{ident}",
            }
        )
        if len(checks) >= _MAX_FINDINGS:
            break
    result["checks"] = checks
    result["recommendations"] = recs
    return result


def parse_codex_cli(report: Path, meta: dict[str, Any]) -> dict[str, Any]:
    step = _step(meta, "codex-cli")
    commands = []
    for name, filename in (
        ("version", "codex-version.out"),
        ("doctor", "codex-doctor.out"),
        ("doctor --json", "codex-doctor-json.out"),
        ("doctor --no-color --all", "codex-doctor-all.out"),
        ("mcp list", "codex-mcp-list.out"),
        ("plugin list", "codex-plugin-list.out"),
        ("features list", "codex-features-list.out"),
    ):
        path = report / "raw" / filename
        commands.append(
            {
                "name": name,
                "raw": f"raw/{filename}" if path.exists() else "",
                "exit_code": _exit_code(report, filename.replace(".out", "")),
            }
        )
    version = ""
    version_text = _read(report / "raw" / "codex-version.out").strip()
    if version_text:
        version = _clip(version_text.splitlines()[0], 120)
    doctor_json = None
    parsed = _load_json(report / "raw" / "codex-doctor-json.out")
    if isinstance(parsed, dict):
        cleaned, _ = redact_obj(parsed)
        encoded = json.dumps(cleaned)
        if len(encoded) <= 20000:
            doctor_json = cleaned
    return {
        "name": "Codex CLI",
        "available": step.get("status") == "ok",
        "status": step.get("status", "skipped"),
        "reason": step.get("reason") or "",
        "version": version,
        "commands": commands,
        "doctor_json": doctor_json,
        "raw": step.get("raw") or [],
    }


def _exit_code(report: Path, name: str) -> int | None:
    path = report / "tmp" / "status" / f"{name}.code"
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def tool_recommendations(*tools: dict[str, Any]) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    for tool in tools:
        for rec in tool.get("recommendations") or []:
            recs.append(rec)
    return recs
