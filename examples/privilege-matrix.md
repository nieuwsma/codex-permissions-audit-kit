# Suggested Privilege Matrix for Codex MCP Plugins & Tools

Use this when reviewing an inventory from `mcp-audit`, `codex mcp list`, or AI Access Auditor.

## Impact Tiers

| Tier | Description | Default recommendation | Approval mode |
|------|-------------|------------------------|---------------|
| **Read-only** | Query, list, get, search | Allow | auto or on-request |
| **Reversible write** | Create, update, comment, transition (non-destructive) | Prompt or scoped auto | prompt |
| **Destructive / high-impact** | Delete, bulk mutate, force-push, filesystem wipe, admin actions | Deny or explicit one-time approval + least-privilege token | forbidden or prompt + review |

## Common MCP Examples

| Server / Tool | Typical capabilities | Suggested minimum | Notes |
|---------------|----------------------|-------------------|-------|
| GitHub official | list issues/PRs, create comments, merge, delete branch | Read + comment | Use fine-grained PAT; disable delete/admin toolsets if possible |
| Linear | search, create/update issues | Read + create | Prefer read-only API token |
| Jira / Atlassian | search, transition, delete issue | Read-only | Permanent delete is high-risk; use scoped OAuth |
| Context7 | docs search | Read | Safe default |
| Filesystem / shell MCP | read/write/execute | Workspace-scoped only | Prefer Codex permission profiles over full MCP FS |
| Postgres / DB | query, insert, drop | Read-only connection string | Separate RO role |

## How to Apply

1. Inventory with `mcp-audit scan` or `codex mcp list`.
2. For each server, set `enabled_tools` / `disabled_tools` and `default_tools_approval_mode = "prompt"` (or `"writes"`) in user `config.toml` where requirements allow.
3. Prefer service accounts or scoped tokens over the developer’s full personal credentials.
4. Enforce the allowlist in `requirements.toml` so unapproved servers cannot start.

## Built-in Codex Profiles (local commands only)

- `:read-only` — no writes
- `:workspace` — writes inside workspace roots + temp
- `:danger-full-access` — no sandbox (deny in requirements)

MCP servers, connectors, and browser/computer-use are controlled separately from these profiles.
