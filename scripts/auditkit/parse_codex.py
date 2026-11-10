# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Read Codex config, rules, requirements, and OpenCode. Never writes those files."""

from __future__ import annotations

import base64
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any

from auditkit.redact import redact_text
from auditkit.snapshot import display_path

_RISKY_SERVER = re.compile(
    r"filesystem|shell|exec|bash|terminal|jira|atlassian|github|linear|"
    r"postgres|mysql|docker|kubectl|aws|slack|browser|computer",
    re.IGNORECASE,
)
_DESTRUCTIVE_TOOL = re.compile(
    r"delete|remove|drop|destroy|merge|force|admin|\brm\b|transition|bulk",
    re.IGNORECASE,
)
_HIGH_PRIV_FEATURE = re.compile(
    r"computer_use|browser_use|danger|yolo|bypass|full_access|unsandboxed",
    re.IGNORECASE,
)
_READONLY_PREFIXES = (
    ["git", "status"],
    ["git", "diff"],
    ["git", "log"],
    ["git", "show"],
    ["ls"],
    ["rg"],
    ["cat"],
    ["pwd"],
)


def _load_toml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, str(exc)
    if len(data) > 1_000_000:
        data = data[:1_000_000]
    try:
        parsed = tomllib.loads(data.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError as exc:
        return None, f"Could not parse {path.name}: {exc}"
    if not isinstance(parsed, dict):
        return None, f"{path.name} did not contain a table"
    return parsed, None


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _approval_text(value: Any) -> tuple[str, str]:
    """Return (kind, display). kind is missing, string, granular, or other."""
    if value is None:
        return "missing", ""
    if isinstance(value, str):
        return "string", value.strip()
    if isinstance(value, dict):
        if "granular" in value:
            return "granular", json.dumps(value, sort_keys=True)
        return "other", json.dumps(value, sort_keys=True)
    return "other", str(value)


def _is_home_path(path: str, home: Path) -> bool:
    raw = path.strip()
    if raw in {"/", "~"}:
        return True
    expanded = Path(raw).expanduser()
    try:
        resolved = expanded.resolve()
        home_resolved = home.resolve()
    except OSError:
        return False
    return resolved == home_resolved or resolved == Path("/")


def _redact_url(url: str) -> str:
    text, _ = redact_text(url)
    text = re.sub(r"//[^/\s:]+:[^/\s@]+@", "//[REDACTED]@", text)
    text = re.sub(r"[?#].*$", "", text)
    return text


def _mcp_servers(table: Any) -> list[dict[str, Any]]:
    if not isinstance(table, dict):
        return []
    servers = []
    for name, cfg in table.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url") if isinstance(cfg.get("url"), str) else ""
        command = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
        args = [str(item) for item in cfg.get("args", [])] if isinstance(cfg.get("args"), list) else []
        args = [redact_text(item)[0] for item in args]
        identity = _redact_url(url) if url else " ".join([command, *args]).strip()
        tool_approvals = []
        tools = cfg.get("tools")
        if isinstance(tools, dict):
            for tool_name, tool_cfg in tools.items():
                mode = None
                if isinstance(tool_cfg, dict):
                    mode = tool_cfg.get("approval_mode")
                tool_approvals.append(
                    {"tool": str(tool_name), "mode": str(mode) if mode else ""}
                )
        mode = cfg.get("default_tools_approval_mode") or cfg.get("approval_mode") or ""
        env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        secret_env_keys = sorted(
            str(key)
            for key in env
            if re.search(r"key|token|secret|password|credential", str(key), re.I)
        )
        enabled = True if "enabled" not in cfg else bool(cfg.get("enabled"))
        risk, reasons = _mcp_risk(str(name), identity, str(mode), tool_approvals, enabled)
        servers.append(
            {
                "name": str(name),
                "transport": "http" if url else "stdio" if command else "unknown",
                "identity": identity,
                "approval_mode": str(mode) if mode else "",
                "tool_approvals": tool_approvals,
                "enabled": enabled,
                "secret_env_keys": secret_env_keys,
                "has_bearer_token": any(
                    key in cfg for key in ("bearer_token", "bearer_token_env_var")
                ),
                "risk": risk,
                "risk_reasons": reasons,
            }
        )
    return servers


def _mcp_risk(
    name: str,
    identity: str,
    mode: str,
    tools: list[dict[str, str]],
    enabled: bool,
) -> tuple[str, list[str]]:
    if not enabled:
        return "ok", ["disabled"]
    blob = f"{name} {identity}"
    risky = bool(_RISKY_SERVER.search(blob))
    destructive = [
        tool["tool"]
        for tool in tools
        if tool.get("mode", "").lower() == "auto" and _DESTRUCTIVE_TOOL.search(tool.get("tool", ""))
    ]
    if destructive:
        return "gap", ["auto approval on " + ", ".join(destructive)]
    lowered = mode.lower()
    if lowered == "auto" and risky:
        return "gap", ["default approval is auto on a write-capable server"]
    if lowered == "auto":
        return "warn", ["default approval is auto"]
    if lowered in {"prompt", "writes", "approve"}:
        return "ok", [f"approval mode {lowered}"]
    if risky:
        return "warn", ["no approval mode on a write-capable server"]
    return "ok", ["no extra approval risk recorded"]


def _features(table: Any) -> list[dict[str, Any]]:
    if not isinstance(table, dict):
        return []
    rows = []
    for name, value in table.items():
        interesting = name == "skill_mcp_dependency_install" or bool(
            _HIGH_PRIV_FEATURE.search(str(name))
        )
        if not interesting:
            continue
        high = _is_true(value) and (
            name == "skill_mcp_dependency_install" or bool(_HIGH_PRIV_FEATURE.search(str(name)))
        )
        note = ""
        if name == "skill_mcp_dependency_install":
            note = "The sample requirements.toml sets skill_mcp_dependency_install to false."
        safe_value: Any
        if isinstance(value, (bool, int, float)) or value is None:
            safe_value = value
        else:
            safe_value, _ = redact_text(str(value))
        rows.append(
            {
                "name": str(name),
                "value": safe_value,
                "high_privilege": high,
                "note": note,
            }
        )
    return rows


def _find_endpoints(value: Any, found: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "headers":
                continue
            if key == "endpoint" and isinstance(item, str):
                found.append(_redact_url(item))
            else:
                _find_endpoints(item, found)


def _otel(table: Any) -> dict[str, Any]:
    if not isinstance(table, dict) or not table:
        return {
            "present": False,
            "exporter": None,
            "endpoint_redacted": None,
            "log_user_prompt": None,
            "log_agent_responses": None,
            "notes": [],
        }
    exporter = table.get("exporter")
    exporter_text = exporter if isinstance(exporter, str) else None
    endpoints: list[str] = []
    _find_endpoints(table, endpoints)
    notes = []
    if _is_true(table.get("log_user_prompt")):
        notes.append("User prompts are exported.")
    if _is_true(table.get("log_agent_responses")):
        notes.append("Agent responses are exported.")
    return {
        "present": True,
        "exporter": exporter_text,
        "endpoint_redacted": endpoints[0] if endpoints else None,
        "log_user_prompt": table.get("log_user_prompt") if "log_user_prompt" in table else None,
        "log_agent_responses": table.get("log_agent_responses")
        if "log_agent_responses" in table
        else None,
        "notes": notes,
    }


def _plugins(table: Any) -> list[dict[str, Any]]:
    if not isinstance(table, dict):
        return []
    rows = []
    for name, cfg in table.items():
        enabled = True
        if isinstance(cfg, dict) and "enabled" in cfg:
            enabled = bool(cfg.get("enabled"))
        rows.append({"name": str(name), "enabled": enabled})
    return rows


def _projects(table: Any, home: Path) -> list[dict[str, Any]]:
    if not isinstance(table, dict):
        return []
    rows = []
    for path, cfg in table.items():
        trust = ""
        if isinstance(cfg, dict) and cfg.get("trust_level") is not None:
            trust = str(cfg.get("trust_level"))
        rows.append(
            {
                "path": str(path),
                "trust_level": trust,
                "is_home": _is_home_path(str(path), home),
            }
        )
    return rows


def parse_config(path: Path, home: Path) -> dict[str, Any]:
    shown = display_path(path, home)
    if not path.exists():
        return {
            "config_path": shown,
            "config_present": False,
            "parse_error": None,
            "posture": _empty_posture(),
            "projects": [],
            "mcp_servers": [],
            "plugins": [],
            "features": [],
            "otel": _otel(None),
        }
    data, error = _load_toml(path)
    if data is None:
        return {
            "config_path": shown,
            "config_present": True,
            "parse_error": error,
            "posture": _empty_posture(),
            "projects": [],
            "mcp_servers": [],
            "plugins": [],
            "features": [],
            "otel": _otel(None),
        }
    kind, approval = _approval_text(data.get("approval_policy"))
    projects = _projects(data.get("projects"), home)
    posture = {
        "approval_policy": approval,
        "approval_policy_kind": kind,
        "sandbox_mode": data.get("sandbox_mode") if isinstance(data.get("sandbox_mode"), str) else None,
        "default_permissions": data.get("default_permissions")
        if isinstance(data.get("default_permissions"), str)
        else None,
        "approvals_reviewer": data.get("approvals_reviewer")
        if isinstance(data.get("approvals_reviewer"), str)
        else None,
        "cli_auth_credentials_store": data.get("cli_auth_credentials_store")
        if isinstance(data.get("cli_auth_credentials_store"), str)
        else None,
        "home_trusted": any(row["is_home"] and row["trust_level"] == "trusted" for row in projects),
    }
    return {
        "config_path": shown,
        "config_present": True,
        "parse_error": None,
        "posture": posture,
        "projects": projects,
        "mcp_servers": _mcp_servers(data.get("mcp_servers")),
        "plugins": _plugins(data.get("plugins")),
        "features": _features(data.get("features")),
        "otel": _otel(data.get("otel")),
    }


def _empty_posture() -> dict[str, Any]:
    return {
        "approval_policy": "",
        "approval_policy_kind": "missing",
        "sandbox_mode": None,
        "default_permissions": None,
        "approvals_reviewer": None,
        "cli_auth_credentials_store": None,
        "home_trusted": False,
    }


def _skip(text: str, index: int) -> int:
    while index < len(text):
        if text[index] in " \t\r\n,":
            index += 1
            continue
        if text[index] == "#":
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        break
    return index


def _parse_string(text: str, index: int) -> tuple[str, int]:
    quote = text[index]
    index += 1
    chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 < len(text):
                chars.append(text[index + 1])
                index += 2
                continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    return "".join(chars), index


def _parse_value(text: str, index: int) -> tuple[Any, int]:
    index = _skip(text, index)
    if index >= len(text):
        return None, index
    if text[index] in "'\"":
        return _parse_string(text, index)
    if text[index] == "[":
        return _parse_list(text, index)
    end = index
    while end < len(text) and text[end] not in ",\n#":
        end += 1
    return text[index:end].strip(), end


def _parse_list(text: str, index: int) -> tuple[list[Any], int]:
    index += 1
    items: list[Any] = []
    while index < len(text):
        index = _skip(text, index)
        if index < len(text) and text[index] == "]":
            return items, index + 1
        value, index = _parse_value(text, index)
        items.append(value)
    raise ValueError("unclosed list")


def _parse_kwargs(body: str) -> dict[str, Any]:
    found: dict[str, Any] = {}
    index = 0
    while index < len(body):
        index = _skip(body, index)
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", body[index:])
        if not match:
            break
        key = match.group(1)
        index += match.end()
        value, index = _parse_value(body, index)
        found[key] = value
    return found


def _match_parens(text: str, open_index: int) -> tuple[str, int]:
    depth = 0
    index = open_index
    quote = ""
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "'\"":
            quote = char
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index], index + 1
        index += 1
    raise ValueError("unbalanced prefix_rule")


def extract_prefix_rules(text: str) -> list[dict[str, Any]]:
    """Pull prefix_rule(...) calls out of a Starlark .rules file. Does not execute it."""
    rules = []
    index = 0
    while True:
        found = text.find("prefix_rule", index)
        if found < 0:
            break
        open_paren = text.find("(", found)
        if open_paren < 0:
            break
        try:
            body, index = _match_parens(text, open_paren)
            kwargs = _parse_kwargs(body)
        except ValueError as exc:
            rules.append({"parse_error": str(exc), "pattern": [], "decision": ""})
            index = open_paren + 1
            continue
        rules.append(
            {
                "pattern": kwargs.get("pattern") if isinstance(kwargs.get("pattern"), list) else [],
                "decision": kwargs.get("decision") if isinstance(kwargs.get("decision"), str) else "",
                "decision_explicit": "decision" in kwargs,
                "justification": kwargs.get("justification")
                if isinstance(kwargs.get("justification"), str)
                else "",
                "parse_error": None,
            }
        )
    return rules


def _tokens(pattern: Any) -> list[str]:
    if isinstance(pattern, str):
        return [pattern]
    if isinstance(pattern, list):
        tokens: list[str] = []
        for item in pattern:
            tokens.extend(_tokens(item))
        return tokens
    return []


def pattern_text(pattern: Any) -> str:
    if isinstance(pattern, str):
        return pattern
    if isinstance(pattern, list):
        parts = []
        for item in pattern:
            if isinstance(item, list):
                parts.append("{" + "|".join(pattern_text(part) for part in item) + "}")
            else:
                parts.append(pattern_text(item))
        return " ".join(part for part in parts if part)
    return ""


def rule_flags(pattern: Any) -> list[str]:
    lowered = [token.lower() for token in _tokens(pattern)]
    flags: set[str] = set()
    if "sudo" in lowered:
        flags.add("sudo")
    if "rm" in lowered:
        flags.add("rm")
    if "curl" in lowered or "wget" in lowered:
        flags.add("curl")
    if "git" in lowered and "push" in lowered:
        flags.add("git_push")
    if "git" in lowered and ("reset" in lowered or "--hard" in lowered):
        flags.add("git_reset")
    installers = {"npm", "pnpm", "yarn", "pip", "pip3", "brew", "uv", "cargo"}
    if any(token in installers for token in lowered) and any(
        token in {"install", "add", "-g"} for token in lowered
    ):
        flags.add("installer")
    if any(token in {"bash", "sh", "zsh"} for token in lowered) and any(
        token in {"-c", "-lc"} for token in lowered
    ):
        flags.add("shell")
    return sorted(flags)


def _readonly_prefix(pattern: Any) -> bool:
    if not isinstance(pattern, list):
        return False
    literals: list[str] = []
    for item in pattern:
        if not isinstance(item, str):
            break
        literals.append(item)
    return any(literals[: len(prefix)] == prefix for prefix in _READONLY_PREFIXES)


def classify_rule(pattern: Any, decision: str, explicit: bool) -> tuple[str, list[str], list[str]]:
    flags = rule_flags(pattern)
    choice = (decision or "allow").strip().lower()
    if not explicit and not decision:
        choice = "allow"
    if choice == "forbidden":
        return "ok", flags, ["forbidden"]
    if choice == "prompt":
        return "ok", flags, ["prompts before running"]
    risky = [flag for flag in flags if flag in {"git_push", "git_reset", "curl", "rm", "sudo", "installer"}]
    if risky:
        return "gap", flags, ["auto-allow " + ", ".join(risky)]
    if "shell" in flags:
        return "warn", flags, ["auto-allow of a shell -c command"]
    if _readonly_prefix(pattern):
        return "ok", flags, ["read-only command prefix"]
    flagged = sorted(set(flags) | {"other"})
    return "warn", flagged, ["auto-allow of a command outside the read-only set"]


def _entry_from_parsed(file_name: str, index: int, parsed: dict[str, Any]) -> dict[str, Any]:
    if parsed.get("parse_error"):
        return {
            "file": file_name,
            "index": index,
            "decision": "",
            "decision_explicit": False,
            "pattern": [],
            "pattern_text": "",
            "justification": "",
            "flags": [],
            "risk": "warn",
            "risk_reasons": [parsed["parse_error"]],
        }
    decision = str(parsed.get("decision") or "")
    explicit = bool(parsed.get("decision_explicit"))
    pattern = parsed.get("pattern") or []
    risk, flags, reasons = classify_rule(pattern, decision, explicit)
    if not explicit and risk != "ok":
        reasons = ["decision omitted; Codex defaults this rule to allow", *reasons]
    return {
        "file": file_name,
        "index": index,
        "decision": (decision or "allow").lower(),
        "decision_explicit": explicit,
        "pattern": pattern,
        "pattern_text": pattern_text(pattern),
        "justification": redact_text(str(parsed.get("justification") or ""))[0],
        "flags": flags,
        "risk": risk,
        "risk_reasons": reasons,
    }


def parse_rules_file(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], str(exc)
    if len(text) > 1_000_000:
        text = text[:1_000_000]
    parsed = extract_prefix_rules(text)
    return [_entry_from_parsed(path.name, index, rule) for index, rule in enumerate(parsed)], None


def parse_rules_dir(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"directory": str(root), "files": [], "entries": []}
    if not root.exists():
        return result
    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        parsed, error = parse_rules_file(path)
        result["files"].append(
            {"path": path.relative_to(root).as_posix(), "parsed": error is None, "error": error}
        )
        entries.extend(parsed)
    result["entries"] = entries
    return result


def _toml_pattern(parts: Any) -> list[Any]:
    pattern: list[Any] = []
    if not isinstance(parts, list):
        return pattern
    for part in parts:
        if isinstance(part, str):
            pattern.append(part)
        elif isinstance(part, dict):
            if "token" in part:
                pattern.append(str(part["token"]))
            elif "any_of" in part and isinstance(part["any_of"], list):
                pattern.append([str(item) for item in part["any_of"]])
    return pattern


def rules_from_requirements(summary: dict[str, Any] | None, file_name: str) -> list[dict[str, Any]]:
    if not summary:
        return []
    entries = []
    for index, rule in enumerate(summary.get("prefix_rules") or []):
        entries.append(_entry_from_parsed(file_name, index, rule))
    return entries


def _requirements_summary(data: dict[str, Any]) -> dict[str, Any]:
    profiles = data.get("allowed_permission_profiles")
    allowed: list[str] = []
    danger = False
    if isinstance(profiles, dict):
        for name, enabled in profiles.items():
            if enabled:
                allowed.append(str(name))
                norm = str(name).strip().lower().lstrip(":")
                if norm == "danger-full-access":
                    danger = True
    policies = data.get("allowed_approval_policies")
    policy_list = [str(item) for item in policies] if isinstance(policies, list) else []
    if any(item in {"never", "on-failure"} for item in policy_list):
        danger = danger or False
    mcp = data.get("mcp_servers")
    mcp_names = sorted(str(name) for name in mcp) if isinstance(mcp, dict) else []
    prefix_rules = []
    rules = data.get("rules")
    if isinstance(rules, dict) and isinstance(rules.get("prefix_rules"), list):
        for rule in rules["prefix_rules"]:
            if not isinstance(rule, dict):
                continue
            prefix_rules.append(
                {
                    "pattern": _toml_pattern(rule.get("pattern")),
                    "decision": str(rule.get("decision") or ""),
                    "decision_explicit": "decision" in rule,
                    "justification": str(rule.get("justification") or ""),
                    "parse_error": None,
                }
            )
    features = data.get("features") if isinstance(data.get("features"), dict) else {}
    safe_features = {}
    for key, value in features.items():
        if isinstance(value, (bool, int, float)) or value is None:
            safe_features[str(key)] = value
        else:
            safe_features[str(key)] = redact_text(str(value))[0]
    default_permissions = data.get("default_permissions")
    if isinstance(default_permissions, str) and default_permissions.strip().lower().lstrip(":") == "danger-full-access":
        danger = True
    return {
        "allowed_approval_policies": policy_list,
        "default_permissions": default_permissions if isinstance(default_permissions, str) else None,
        "allowed_permission_profiles": allowed,
        "danger_full_access_allowed": danger,
        "allows_never": any(item in {"never", "on-failure"} for item in policy_list),
        "mcp_server_names": mcp_names,
        "features": safe_features,
        "prefix_rules": prefix_rules,
    }


def _location(
    item_id: str,
    path: str,
    status: str,
    reason: str,
    summary: dict[str, Any] | None = None,
    sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "path": path,
        "status": status,
        "reason": reason,
        "sha256": sha256,
        "summary": summary,
    }


def parse_requirements_file(path: Path) -> dict[str, Any]:
    shown = str(path)
    if not path.exists():
        return _location("etc", shown, "absent", "File is not present.")
    if not os.access(path, os.R_OK):
        return _location(
            "etc",
            shown,
            "unreadable",
            "The file exists but is not readable without elevated privileges. sudo was not used.",
        )
    data, error = _load_toml(path)
    if data is None:
        return _location("etc", shown, "present", error or "Could not parse the file.")
    import hashlib

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return _location("etc", shown, "present", "", _requirements_summary(data), digest)


def parse_mdm_output(text: str, exit_code: int | None) -> dict[str, Any]:
    """Interpret `defaults read com.openai.codex requirements_toml_base64`."""
    path = "MDM com.openai.codex requirements_toml_base64"
    stripped = text.strip()
    if exit_code not in (0, None) or not stripped or "does not exist" in stripped.lower():
        return _location("mdm", path, "absent", "No com.openai.codex MDM payload was readable.")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "'\"":
        stripped = stripped[1:-1]
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except Exception:
        return _location("mdm", path, "present", "The MDM value was not valid base64.", sha256=None)
    import hashlib

    digest = hashlib.sha256(decoded).hexdigest()
    try:
        parsed = tomllib.loads(decoded.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError as exc:
        return _location("mdm", path, "present", f"Decoded payload was not TOML: {exc}", sha256=digest)
    if not isinstance(parsed, dict):
        return _location("mdm", path, "present", "Decoded payload was not a table.", sha256=digest)
    return _location("mdm", path, "present", "", _requirements_summary(parsed), digest)


def parse_opencode(path: Path, home: Path) -> dict[str, Any]:
    shown = display_path(path, home)
    result: dict[str, Any] = {
        "path": shown,
        "present": path.exists(),
        "parse_error": None,
        "share": None,
        "permissions": {},
        "mcp_servers": [],
        "notes": [],
    }
    if not path.exists():
        return result
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result["parse_error"] = str(exc)
        return result
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        result["parse_error"] = f"Could not parse JSON: {exc}"
        return result
    if not isinstance(data, dict):
        result["parse_error"] = "OpenCode config was not a JSON object."
        return result
    share = data.get("share")
    result["share"] = share if isinstance(share, str) else None
    permissions = data.get("permission") if isinstance(data.get("permission"), dict) else {}
    if not permissions and isinstance(data.get("permissions"), dict):
        permissions = data["permissions"]
    safe_permissions = {}
    for key, value in permissions.items():
        if isinstance(value, str) and len(value) < 40:
            safe_permissions[str(key)] = redact_text(value)[0]
        elif isinstance(value, (bool, int)):
            safe_permissions[str(key)] = value
    result["permissions"] = safe_permissions
    mcp = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
    result["mcp_servers"] = sorted(str(name) for name in mcp)
    if result["share"] == "auto":
        result["notes"].append("share is auto, so new sessions can be published to a link.")
    for key in ("bash", "shell"):
        if str(safe_permissions.get(key, "")).lower() == "allow":
            result["notes"].append(f"permission {key} is allow.")
    return result
