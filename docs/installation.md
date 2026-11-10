# Installation Guide

## 1. mcp-audit (recommended first local scanner)

Python 3.11+.

```bash
pip install mcp-audit-scanner
# or
uv add mcp-audit-scanner
```

Usage:

```bash
mcp-audit                          # static review of supported configs
mcp-audit scan --project .         # project + agent files
mcp-audit check                    # grade setup
mcp-audit explain MCP007           # offline explanation of a finding
```

Standalone binaries: https://github.com/adudley78/mcp-audit/releases

## 2. Codex Security Audit (AI Security Labs)

Requires Docker or Podman.

```bash
git clone https://github.com/aisecuritylabs-org/coding-agent-security.git ~/coding-agent-security
cd /path/to/your/project
bash ~/coding-agent-security/codex/audit/run.sh
```

Produces PASS/WARN/FAIL summary; optional HTML/JSON report. Offline container.

## 3. AI Access Auditor

Desktop app (macOS/Windows/Linux) that inventories Codex, Claude Code, Cursor, etc.

- Download: https://github.com/dirmedmr-alt/ai-access-auditor/releases
- Or build: clone + `./build-app.sh` (needs Node)

Shows permission grants, MCP servers, and lets you revoke.

## 4. Built-in Codex commands

```bash
codex doctor          # effective config + requirements conflicts
codex mcp list        # active MCP servers
codex --profile :read-only   # test a profile
```

## 5. Deploying requirements.toml

- **Cloud (preferred for enterprise)**: ChatGPT admin → Codex Policies → create managed requirements.
- **MDM (macOS)**: `com.openai.codex` preference `requirements_toml_base64`.
- **File**: `/etc/codex/requirements.toml` (Unix) or `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows).

Precedence (later overrides earlier): system file → cloud-managed → MDM.

Validate with `codex doctor` after sign-in.

## Tips

- Run scanners on a representative developer laptop (CLI + IDE extension).
- Prefer scoped credentials for any MCP that talks to Jira, GitHub, Linear, etc.
- Re-run after policy changes; use OpenTelemetry export or Compliance API for ongoing visibility.
