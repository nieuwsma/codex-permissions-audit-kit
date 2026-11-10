# Codex Permissions Audit Kit

Starter kit for auditing and locking down permissions on OpenAI Codex (CLI and IDE extension) in enterprise environments.

Focus: prevent over-privileged agentic use of MCP plugins and local tools (e.g., full disk access, destructive Jira operations) by combining central `requirements.toml` enforcement with local discovery scanners.

## Quick Start

1. Review and adapt `examples/requirements.toml` for your ChatGPT Business/Enterprise workspace or MDM delivery.
2. Install the recommended local scanners (see `docs/installation.md`).
3. Run a local audit on a developer machine to inventory current MCP servers, permission profiles, and approval policies.
4. Map findings to the privilege matrix in `examples/privilege-matrix.md` and tighten allowlists / approval modes.
5. Deploy the managed policy; use `codex doctor` to validate.

## What This Addresses

- Users enabling full disk / `danger-full-access` without realizing the blast radius.
- MCP plugins (Jira, GitHub, Linear, etc.) that inherit write/delete scopes when only read is needed.
- Lack of a local “what can this account/box actually do?” inventory.

CLI and IDE extension share `~/.codex/config.toml` and the same sandbox / permission-profile model. Enterprise accounts receive cloud-managed requirements on sign-in.

## Recommended Local Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **mcp-audit** (mcp-audit-scanner) | Enumerate MCP servers, risk-score tools, detect secrets & excessive permissions | `pip install mcp-audit-scanner` |
| **Codex Security Audit** (AI Security Labs) | Offline check of config.toml, sandbox, hooks, MCP inventory against security guide | Clone + Docker (see docs) |
| **AI Access Auditor** | GUI/CLI inventory of agent permissions across Codex, Claude Code, Cursor, etc. | Download app or build from source |
| **codex doctor** | Built-in: shows effective config layers, requirements conflicts | Ships with Codex CLI |

## Enterprise Controls (preferred)

Use managed `requirements.toml` (cloud, MDM, or `/etc/codex/requirements.toml`) to:

- Restrict `allowed_permission_profiles` (omit `:danger-full-access`).
- Allowlist MCP servers by name + identity (command or URL).
- Force `on-request` approvals.
- Pin network, web search, and feature flags.

See official docs: https://developers.openai.com/codex/enterprise/managed-configuration/

## Privilege Matrix (summary)

| Impact | Examples | Suggested default |
|--------|----------|-------------------|
| Read-only | search, get issue, list PRs | Always allow |
| Reversible write | create comment, update description | Prompt or auto with review |
| Destructive / high-impact | delete issue, bulk transition, force push, rm -rf | Deny or explicit approval + scoped credential |

Full matrix and MCP examples: `examples/privilege-matrix.md`

## License

MIT (adapt as needed for internal use).
