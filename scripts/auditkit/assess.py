# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Privilege-matrix checks and heuristic recommendations.

The rule ids here are the contract documented in docs/recommendation-rules.md.
A gap or warn check becomes a recommendation. An ok or info check stays in the
matrix. Heuristics are recommendations only.
"""

from __future__ import annotations

from typing import Any

KM_IDS = [
    "KM-APPROVAL",
    "KM-DANGER-PROFILE",
    "KM-LEGACY-SANDBOX",
    "KM-SANDBOX-AND-PROFILE",
    "KM-HOME-TRUSTED",
    "KM-TRUSTED-PROJECTS",
    "KM-RULE-GIT-PUSH",
    "KM-RULE-GIT-RESET",
    "KM-RULE-CURL",
    "KM-RULE-RM",
    "KM-RULE-SUDO",
    "KM-RULE-INSTALLER",
    "KM-RULE-OTHER-ALLOW",
    "KM-MCP-APPROVAL",
    "KM-FEATURE-INSTALL",
    "KM-FEATURE-HIGH-PRIV",
    "KM-OTEL-PROMPTS",
    "KM-REQUIREMENTS",
    "KM-REQUIREMENTS-PROFILES",
    "KM-OPENCODE-SHARE",
    "KM-PLUGINS",
]

HEURISTIC_IDS = [
    "H-NEVER-AND-DANGER",
    "H-HOME-AND-RM",
    "H-AUTH-FILE",
    "H-AUTO-REVIEW",
    "H-OPENCODE-SHELL",
]

RULE_IDS = KM_IDS + HEURISTIC_IDS

_GAP_PRIORITY = {
    "KM-APPROVAL": "critical",
    "KM-DANGER-PROFILE": "critical",
    "KM-HOME-TRUSTED": "critical",
    "KM-RULE-RM": "critical",
    "KM-RULE-SUDO": "critical",
    "KM-RULE-GIT-PUSH": "high",
    "KM-RULE-GIT-RESET": "high",
    "KM-RULE-CURL": "high",
    "KM-RULE-INSTALLER": "high",
    "KM-MCP-APPROVAL": "high",
    "KM-FEATURE-HIGH-PRIV": "high",
    "KM-REQUIREMENTS-PROFILES": "critical",
    "KM-OPENCODE-SHARE": "high",
    "KM-LEGACY-SANDBOX": "medium",
    "KM-SANDBOX-AND-PROFILE": "medium",
    "KM-FEATURE-INSTALL": "medium",
    "KM-OTEL-PROMPTS": "medium",
    "KM-REQUIREMENTS": "medium",
    "KM-RULE-OTHER-ALLOW": "medium",
}


def _norm(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower().lstrip(":")


def _is_danger(posture: dict[str, Any]) -> bool:
    return _norm(posture.get("sandbox_mode")) == "danger-full-access" or _norm(
        posture.get("default_permissions")
    ) == "danger-full-access"


def _row(
    rule_id: str,
    title: str,
    status: str,
    expected: str,
    observed: str,
    advice: str = "",
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    check = {
        "id": rule_id,
        "title": title,
        "status": status,
        "expected": expected,
        "observed": observed,
        "source": "kit-matrix",
    }
    if status not in {"gap", "warn"}:
        return check, None
    priority = _GAP_PRIORITY.get(rule_id, "medium")
    if status == "warn":
        priority = "medium"
    return check, {
        "id": rule_id,
        "priority": priority,
        "source": "kit-matrix",
        "tool": None,
        "title": title,
        "detail": advice or observed,
        "rule_id": rule_id,
    }


def _list_patterns(entries: list[dict[str, Any]]) -> str:
    texts = [entry.get("pattern_text") or "(unparsed rule)" for entry in entries[:8]]
    extra = len(entries) - len(texts)
    shown = ", ".join(texts) if texts else "none"
    if extra > 0:
        shown += f", and {extra} more"
    return shown


def _allowing(entries: list[dict[str, Any]], flag: str, risk: str) -> list[dict[str, Any]]:
    return [
        entry
        for entry in entries
        if entry.get("decision") == "allow" and flag in (entry.get("flags") or []) and entry.get("risk") == risk
    ]


def _rule_check(
    rule_id: str,
    title: str,
    entries: list[dict[str, Any]],
    flag: str,
    expected: str,
    advice: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    matched = _allowing(entries, flag, "gap")
    if matched:
        return _row(rule_id, title, "gap", expected, _list_patterns(matched), advice)
    return _row(rule_id, title, "ok", expected, "No matching auto-allow rule.")


def build_matrix(local: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    config = local["config"]
    posture = config["posture"]
    entries = local["rules"]["entries"]
    checks: list[dict[str, Any]] = []
    recs: list[dict[str, Any]] = []

    def add(pair: tuple[dict[str, Any], dict[str, Any] | None]) -> None:
        check, rec = pair
        checks.append(check)
        if rec:
            recs.append(rec)

    if not config["config_present"]:
        add(
            _row(
                "KM-APPROVAL",
                "Approval policy is on-request",
                "skipped",
                "approval_policy = on-request",
                "config.toml is not present.",
            )
        )
    elif config.get("parse_error"):
        add(
            _row(
                "KM-APPROVAL",
                "Approval policy is on-request",
                "skipped",
                "approval_policy = on-request",
                config["parse_error"],
            )
        )
    else:
        kind = posture.get("approval_policy_kind")
        value = posture.get("approval_policy") or ""
        if kind == "missing":
            add(
                _row(
                    "KM-APPROVAL",
                    "Approval policy is on-request",
                    "warn",
                    "approval_policy = on-request",
                    "approval_policy is not set.",
                    "Set approval_policy to on-request, or enforce that value in managed requirements.toml.",
                )
            )
        elif kind == "granular":
            add(
                _row(
                    "KM-APPROVAL",
                    "Approval policy is on-request",
                    "warn",
                    "approval_policy = on-request",
                    "approval_policy is granular: " + value,
                    "Review which prompt categories are suppressed. Prefer on-request unless each category is intentional.",
                )
            )
        elif value in {"never", "on-failure", "untrusted"}:
            add(
                _row(
                    "KM-APPROVAL",
                    "Approval policy is on-request",
                    "gap",
                    "approval_policy = on-request",
                    f"approval_policy = {value}.",
                    "Use approval_policy = on-request so Codex asks before it runs a command. The sample requirements allow only on-request.",
                )
            )
        elif value == "on-request":
            add(
                _row(
                    "KM-APPROVAL",
                    "Approval policy is on-request",
                    "ok",
                    "approval_policy = on-request",
                    "approval_policy = on-request.",
                )
            )
        else:
            add(
                _row(
                    "KM-APPROVAL",
                    "Approval policy is on-request",
                    "warn",
                    "approval_policy = on-request",
                    f"Unrecognized approval_policy {value}.",
                    "Set approval_policy to on-request.",
                )
            )

    if not config["config_present"] or config.get("parse_error"):
        observed = "config.toml is not present." if not config["config_present"] else config["parse_error"]
        for rule_id, title, expected in (
            ("KM-DANGER-PROFILE", "Danger-full-access is not the default", "default_permissions is :workspace or :read-only, and sandbox_mode is not danger-full-access"),
            ("KM-LEGACY-SANDBOX", "Legacy sandbox_mode is unset", "Prefer default_permissions and leave sandbox_mode unset."),
            ("KM-SANDBOX-AND-PROFILE", "sandbox_mode and default_permissions are not both set", "Do not combine them. sandbox_mode wins and permission profiles are ignored."),
            ("KM-HOME-TRUSTED", "The home directory is not a trusted project", "Do not set trust_level = trusted on $HOME or /."),
        ):
            add(_row(rule_id, title, "skipped", expected, observed))
    else:
        sandbox = posture.get("sandbox_mode")
        permissions = posture.get("default_permissions")
        if _is_danger(posture):
            which = sandbox if _norm(sandbox) == "danger-full-access" else permissions
            add(
                _row(
                    "KM-DANGER-PROFILE",
                    "Danger-full-access is not the default",
                    "gap",
                    "default_permissions is :workspace or :read-only, and sandbox_mode is not danger-full-access",
                    f"A danger-full-access setting is active ({which}).",
                    "Remove danger-full-access. Use :workspace or :read-only. The sample allowed_permission_profiles list omits :danger-full-access.",
                )
            )
        elif _norm(permissions) in {"read-only", "workspace"} or _norm(sandbox) in {
            "read-only",
            "workspace-write",
        }:
            add(
                _row(
                    "KM-DANGER-PROFILE",
                    "Danger-full-access is not the default",
                    "ok",
                    "default_permissions is :workspace or :read-only, and sandbox_mode is not danger-full-access",
                    f"sandbox_mode={sandbox or 'unset'}, default_permissions={permissions or 'unset'}.",
                )
            )
        elif not sandbox and not permissions:
            add(
                _row(
                    "KM-DANGER-PROFILE",
                    "Danger-full-access is not the default",
                    "warn",
                    "default_permissions is :workspace or :read-only, and sandbox_mode is not danger-full-access",
                    "Neither default_permissions nor sandbox_mode is set.",
                    "Set default_permissions to :workspace or :read-only.",
                )
            )
        else:
            add(
                _row(
                    "KM-DANGER-PROFILE",
                    "Danger-full-access is not the default",
                    "warn",
                    "default_permissions is :workspace or :read-only, and sandbox_mode is not danger-full-access",
                    f"Unrecognized profile sandbox_mode={sandbox}, default_permissions={permissions}.",
                    "Set default_permissions to :workspace or :read-only.",
                )
            )
        if sandbox:
            add(
                _row(
                    "KM-LEGACY-SANDBOX",
                    "Legacy sandbox_mode is unset",
                    "warn",
                    "Prefer default_permissions and leave sandbox_mode unset.",
                    f"sandbox_mode = {sandbox}.",
                    "Prefer default_permissions. When sandbox_mode is set, Codex uses the legacy sandbox instead of permission profiles.",
                )
            )
        else:
            add(
                _row(
                    "KM-LEGACY-SANDBOX",
                    "Legacy sandbox_mode is unset",
                    "ok",
                    "Prefer default_permissions and leave sandbox_mode unset.",
                    "sandbox_mode is not set.",
                )
            )
        if sandbox and permissions:
            add(
                _row(
                    "KM-SANDBOX-AND-PROFILE",
                    "sandbox_mode and default_permissions are not both set",
                    "warn",
                    "Do not combine them. sandbox_mode wins and permission profiles are ignored.",
                    f"Both are set: sandbox_mode={sandbox}, default_permissions={permissions}.",
                    "Remove sandbox_mode and keep a single default_permissions value.",
                )
            )
        else:
            add(
                _row(
                    "KM-SANDBOX-AND-PROFILE",
                    "sandbox_mode and default_permissions are not both set",
                    "ok",
                    "Do not combine them. sandbox_mode wins and permission profiles are ignored.",
                    "The two settings are not both set.",
                )
            )
        home_rows = [
            row for row in config["projects"] if row.get("is_home") and row.get("trust_level") == "trusted"
        ]
        if home_rows:
            add(
                _row(
                    "KM-HOME-TRUSTED",
                    "The home directory is not a trusted project",
                    "gap",
                    "Do not set trust_level = trusted on $HOME or /.",
                    "Trusted home path: " + ", ".join(row["path"] for row in home_rows),
                    "Mark the home directory untrusted. A trusted home loads project rules and config for every file under it.",
                )
            )
        else:
            add(
                _row(
                    "KM-HOME-TRUSTED",
                    "The home directory is not a trusted project",
                    "ok",
                    "Do not set trust_level = trusted on $HOME or /.",
                    "Home is not a trusted project.",
                )
            )

    others = [
        row
        for row in config.get("projects") or []
        if row.get("trust_level") == "trusted" and not row.get("is_home")
    ]
    if others:
        shown = ", ".join(row["path"] for row in others[:8])
        add(
            _row(
                "KM-TRUSTED-PROJECTS",
                "Trusted projects are limited to repositories you meant to trust",
                "info",
                "Trust a project only when its .codex layer should load.",
                f"{len(others)} trusted project(s): {shown}",
            )
        )
    else:
        add(
            _row(
                "KM-TRUSTED-PROJECTS",
                "Trusted projects are limited to repositories you meant to trust",
                "ok",
                "Trust a project only when its .codex layer should load.",
                "No trusted projects outside the home directory.",
            )
        )

    add(
        _rule_check(
            "KM-RULE-GIT-PUSH",
            "git push is not auto-allowed",
            entries,
            "git_push",
            "decision prompt or forbidden for git push.",
            "Change the git push allow rule to prompt or forbidden. The sample requirements.toml prompts before git push.",
        )
    )
    add(
        _rule_check(
            "KM-RULE-GIT-RESET",
            "git reset / --hard is not auto-allowed",
            entries,
            "git_reset",
            "decision prompt or forbidden for git reset and --hard.",
            "Change the git reset allow rule to prompt or forbidden.",
        )
    )
    add(
        _rule_check(
            "KM-RULE-CURL",
            "curl and wget are not auto-allowed",
            entries,
            "curl",
            "decision prompt or forbidden for curl and wget.",
            "Change the curl or wget allow rule to prompt or forbidden. An allow rule lets a fetched script run outside the sandbox.",
        )
    )
    add(
        _rule_check(
            "KM-RULE-RM",
            "rm is not auto-allowed",
            entries,
            "rm",
            "decision prompt or forbidden for rm.",
            "Change the rm allow rule to forbidden or prompt. The sample requirements.toml forbids rm -rf, rm -r, and rm -f.",
        )
    )
    add(
        _rule_check(
            "KM-RULE-SUDO",
            "sudo is not auto-allowed",
            entries,
            "sudo",
            "decision forbidden or prompt for sudo.",
            "Remove the sudo allow rule. The audit itself does not use sudo.",
        )
    )
    add(
        _rule_check(
            "KM-RULE-INSTALLER",
            "Package installers are not auto-allowed",
            entries,
            "installer",
            "decision prompt or forbidden for npm, pip, brew, uv, and similar installers.",
            "Change the installer allow rule to prompt. Installers can fetch and run code.",
        )
    )
    other = [
        entry
        for entry in entries
        if entry.get("decision") == "allow" and entry.get("risk") == "warn"
    ]
    if other:
        add(
            _row(
                "KM-RULE-OTHER-ALLOW",
                "Other auto-allow rules are read-only",
                "warn",
                "Auto-allow only read-only prefixes such as git status, git diff, ls, or rg.",
                _list_patterns(other),
                "Review these allow rules. Codex defaults a prefix_rule with no decision to allow, which runs the command outside the sandbox.",
            )
        )
    else:
        add(
            _row(
                "KM-RULE-OTHER-ALLOW",
                "Other auto-allow rules are read-only",
                "ok",
                "Auto-allow only read-only prefixes such as git status, git diff, ls, or rg.",
                "No extra auto-allow rules.",
            )
        )

    servers = config.get("mcp_servers") or []
    if not config["config_present"] or config.get("parse_error"):
        add(
            _row(
                "KM-MCP-APPROVAL",
                "MCP servers do not auto-approve writes",
                "skipped",
                "Write-capable servers use prompt, writes, or approve.",
                "config.toml could not be read.",
            )
        )
    elif any(server.get("risk") == "gap" for server in servers):
        names = [server["name"] for server in servers if server.get("risk") == "gap"]
        add(
            _row(
                "KM-MCP-APPROVAL",
                "MCP servers do not auto-approve writes",
                "gap",
                "Write-capable servers use prompt, writes, or approve.",
                "Gap on " + ", ".join(names),
                "Set default_tools_approval_mode to prompt for those servers, and do not auto-approve destructive tools.",
            )
        )
    elif any(server.get("risk") == "warn" for server in servers):
        names = [server["name"] for server in servers if server.get("risk") == "warn"]
        add(
            _row(
                "KM-MCP-APPROVAL",
                "MCP servers do not auto-approve writes",
                "warn",
                "Write-capable servers use prompt, writes, or approve.",
                "Warning on " + ", ".join(names),
                "Set an explicit approval mode. Auto, or a missing mode on a write-capable server, is broader than the privilege matrix.",
            )
        )
    else:
        add(
            _row(
                "KM-MCP-APPROVAL",
                "MCP servers do not auto-approve writes",
                "ok",
                "Write-capable servers use prompt, writes, or approve.",
                "No MCP approval gaps." if servers else "No MCP servers in config.toml.",
            )
        )

    features = {row["name"]: row for row in config.get("features") or []}
    install = features.get("skill_mcp_dependency_install")
    if install and install.get("value") is True:
        add(
            _row(
                "KM-FEATURE-INSTALL",
                "skill_mcp_dependency_install is off",
                "warn",
                "skill_mcp_dependency_install = false, matching the sample requirements.toml.",
                "skill_mcp_dependency_install = true.",
                "Set skill_mcp_dependency_install to false so Codex does not install MCP dependencies on its own.",
            )
        )
    else:
        observed = "skill_mcp_dependency_install is false or unset."
        add(
            _row(
                "KM-FEATURE-INSTALL",
                "skill_mcp_dependency_install is off",
                "ok",
                "skill_mcp_dependency_install = false, matching the sample requirements.toml.",
                observed,
            )
        )
    high = [
        row["name"]
        for row in config.get("features") or []
        if row.get("high_privilege") and row["name"] != "skill_mcp_dependency_install"
    ]
    if high:
        add(
            _row(
                "KM-FEATURE-HIGH-PRIV",
                "High-privilege feature flags are off",
                "gap",
                "computer use, browser use, and bypass-style features stay off.",
                "Enabled: " + ", ".join(high),
                "Turn those feature flags off unless a managed policy explicitly allows them.",
            )
        )
    else:
        add(
            _row(
                "KM-FEATURE-HIGH-PRIV",
                "High-privilege feature flags are off",
                "ok",
                "computer use, browser use, and bypass-style features stay off.",
                "No high-privilege feature is enabled.",
            )
        )

    otel = config.get("otel") or {}
    if otel.get("log_user_prompt") is True or otel.get("log_agent_responses") is True:
        bits = []
        if otel.get("log_user_prompt") is True:
            bits.append("log_user_prompt")
        if otel.get("log_agent_responses") is True:
            bits.append("log_agent_responses")
        add(
            _row(
                "KM-OTEL-PROMPTS",
                "OpenTelemetry does not export prompts or responses",
                "warn",
                "Leave log_user_prompt and log_agent_responses unset or false.",
                "Enabled: " + ", ".join(bits),
                "Turn off prompt and response export. Those logs can contain source code and credentials.",
            )
        )
    else:
        add(
            _row(
                "KM-OTEL-PROMPTS",
                "OpenTelemetry does not export prompts or responses",
                "ok",
                "Leave log_user_prompt and log_agent_responses unset or false.",
                "Prompt and response export are not enabled.",
            )
        )

    locations = (local.get("requirements") or {}).get("locations") or []
    present = [item for item in locations if item.get("status") == "present" and item.get("summary")]
    unreadable = [item for item in locations if item.get("status") == "unreadable"]
    if present:
        names = ", ".join(item["path"] for item in present)
        add(
            _row(
                "KM-REQUIREMENTS",
                "Managed requirements are deployed",
                "ok",
                "A managed requirements.toml is in place, as in the sample.",
                "Present: " + names,
            )
        )
        if any((item.get("summary") or {}).get("danger_full_access_allowed") or (item.get("summary") or {}).get("allows_never") for item in present):
            add(
                _row(
                    "KM-REQUIREMENTS-PROFILES",
                    "Managed requirements omit danger-full-access and never",
                    "gap",
                    "The sample allows :read-only and :workspace, and approval on-request only.",
                    "A managed requirements file allows danger-full-access or an approval policy of never or on-failure.",
                    "Remove :danger-full-access from allowed_permission_profiles and do not allow the never approval policy.",
                )
            )
        else:
            add(
                _row(
                    "KM-REQUIREMENTS-PROFILES",
                    "Managed requirements omit danger-full-access and never",
                    "ok",
                    "The sample allows :read-only and :workspace, and approval on-request only.",
                    "Managed requirements do not allow danger-full-access or never.",
                )
            )
    elif unreadable:
        add(
            _row(
                "KM-REQUIREMENTS",
                "Managed requirements are deployed",
                "skipped",
                "A managed requirements.toml is in place, as in the sample.",
                unreadable[0].get("reason") or "requirements.toml is not readable.",
            )
        )
        add(
            _row(
                "KM-REQUIREMENTS-PROFILES",
                "Managed requirements omit danger-full-access and never",
                "skipped",
                "The sample allows :read-only and :workspace, and approval on-request only.",
                "The managed file could not be read.",
            )
        )
    else:
        add(
            _row(
                "KM-REQUIREMENTS",
                "Managed requirements are deployed",
                "warn",
                "A managed requirements.toml is in place, as in the sample.",
                "No /etc/codex/requirements.toml and no readable MDM payload.",
                "Deploy managed requirements so a user config cannot select danger-full-access or approval never. See examples/requirements.toml.",
            )
        )
        add(
            _row(
                "KM-REQUIREMENTS-PROFILES",
                "Managed requirements omit danger-full-access and never",
                "skipped",
                "The sample allows :read-only and :workspace, and approval on-request only.",
                "No managed requirements were available to compare.",
            )
        )

    opencode = local.get("opencode") or {}
    if not opencode.get("present"):
        add(
            _row(
                "KM-OPENCODE-SHARE",
                "OpenCode does not auto-share sessions",
                "ok",
                "share is not auto.",
                "opencode.json is not present.",
            )
        )
    elif opencode.get("share") == "auto":
        add(
            _row(
                "KM-OPENCODE-SHARE",
                "OpenCode does not auto-share sessions",
                "gap",
                "share is not auto.",
                "opencode.json sets share = auto.",
                "Set OpenCode share to manual so sessions are not published to a link.",
            )
        )
    else:
        add(
            _row(
                "KM-OPENCODE-SHARE",
                "OpenCode does not auto-share sessions",
                "ok",
                "share is not auto.",
                f"share = {opencode.get('share') or 'unset'}.",
            )
        )

    enabled = [plugin["name"] for plugin in config.get("plugins") or [] if plugin.get("enabled")]
    if enabled:
        add(
            _row(
                "KM-PLUGINS",
                "Enabled plugins are known",
                "info",
                "Each enabled plugin is one you intend to run.",
                "Enabled: " + ", ".join(enabled),
            )
        )
    else:
        add(
            _row(
                "KM-PLUGINS",
                "Enabled plugins are known",
                "ok",
                "Each enabled plugin is one you intend to run.",
                "No enabled plugins in config.toml.",
            )
        )
    return checks, recs


def build_heuristics(local: dict[str, Any], auth_present: bool) -> list[dict[str, Any]]:
    config = local["config"]
    posture = config.get("posture") or {}
    entries = local["rules"]["entries"]
    recs = []
    approval = (posture.get("approval_policy") or "").lower()
    if approval in {"never", "on-failure"} and _is_danger(posture):
        recs.append(
            {
                "id": "H-NEVER-AND-DANGER",
                "priority": "critical",
                "source": "heuristic",
                "tool": None,
                "title": "Approvals are off and the sandbox is fully open",
                "detail": (
                    "approval_policy is "
                    + approval
                    + " and a danger-full-access setting is active. Together those settings let Codex run commands without asking and without a sandbox. Change the approval policy to on-request and leave danger-full-access unset."
                ),
                "rule_id": "H-NEVER-AND-DANGER",
            }
        )
    home = posture.get("home_trusted")
    rm_rules = _allowing(entries, "rm", "gap")
    if home and rm_rules:
        recs.append(
            {
                "id": "H-HOME-AND-RM",
                "priority": "critical",
                "source": "heuristic",
                "tool": None,
                "title": "Home is trusted and rm is auto-allowed",
                "detail": "A trusted home plus an rm allow rule can delete files anywhere under the home directory without a prompt. Untrust home and forbid the rm rule.",
                "rule_id": "H-HOME-AND-RM",
            }
        )
    store = (posture.get("cli_auth_credentials_store") or "").lower()
    if auth_present and store != "keyring":
        recs.append(
            {
                "id": "H-AUTH-FILE",
                "priority": "medium",
                "source": "heuristic",
                "tool": None,
                "title": "Codex auth.json is a file on disk",
                "detail": "auth.json is present. This audit did not open it. Codex can store the login in the system keyring instead (cli_auth_credentials_store = keyring) so other programs are less likely to read the file.",
                "rule_id": "H-AUTH-FILE",
            }
        )
    if (posture.get("approvals_reviewer") or "").lower() == "auto_review":
        recs.append(
            {
                "id": "H-AUTO-REVIEW",
                "priority": "medium",
                "source": "heuristic",
                "tool": None,
                "title": "An automatic reviewer can answer approval prompts",
                "detail": "approvals_reviewer = auto_review. Prompts can be decided without a person. Prefer the user reviewer when the privilege matrix calls for a prompt.",
                "rule_id": "H-AUTO-REVIEW",
            }
        )
    permissions = (local.get("opencode") or {}).get("permissions") or {}
    if any(str(permissions.get(key, "")).lower() == "allow" for key in ("bash", "shell")):
        recs.append(
            {
                "id": "H-OPENCODE-SHELL",
                "priority": "medium",
                "source": "heuristic",
                "tool": None,
                "title": "OpenCode allows the shell",
                "detail": "opencode.json sets bash or shell permission to allow. That is broader than a prompt. Set it to ask.",
                "rule_id": "H-OPENCODE-SHELL",
            }
        )
    return recs


def posture_of(checks: list[dict[str, Any]]) -> str:
    statuses = {check["status"] for check in checks}
    if "gap" in statuses:
        return "gap"
    if "warn" in statuses:
        return "warn"
    return "ok"


def headline_for(checks: list[dict[str, Any]]) -> str:
    def observed(check: dict[str, Any]) -> str:
        return str(check.get("observed") or "").rstrip().rstrip(".")

    gaps = [observed(check) for check in checks if check["status"] == "gap" and observed(check)]
    warns = [observed(check) for check in checks if check["status"] == "warn" and observed(check)]
    if gaps:
        return "Gaps against the privilege matrix: " + "; ".join(gaps[:3]) + "."
    if warns:
        return "No matrix gaps. Warnings: " + "; ".join(warns[:3]) + "."
    return "The recorded settings match the privilege matrix checks that ran."


def combine_recommendations(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    merged: dict[str, dict[str, Any]] = {}
    for group in groups:
        for rec in group:
            current = merged.get(rec["id"])
            if current is None or order.get(rec["priority"], 9) < order.get(current["priority"], 9):
                merged[rec["id"]] = rec
    return sorted(merged.values(), key=lambda rec: (order.get(rec["priority"], 9), rec["id"]))
