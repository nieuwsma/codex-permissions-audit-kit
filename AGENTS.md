# Agent instructions

This repository is a read-only permissions audit kit. Run the audit and explain the results.

## Do not change configuration

Do not change configuration. Do not edit `~/.codex`, `~/.config/opencode`, rules, requirements, or shell startup files. Do not apply recommendations. Do not run fix, lock, pin, register, push-nucleus, revoke, redact, or hook install. Do not pass `--connect` to mcp-audit. Do not use sudo. Do not grant Full Disk Access or any other TCC permission. Do not open, print, or copy `auth.json`.

If `verification.ok` is false, say which watched file changed and stop. Do not try to repair it.

## Run the audit

From the repository root:

```bash
bash scripts/full-readonly-audit.sh
```

Optional scanners that download code or build a container stay off unless the person asked for them:

- `--with-mcp-audit`
- `--with-access-auditor`
- `--with-aisec-audit`

A missing tool is a skipped check. Do not install it on your own.

## Read the report

The script writes `reports/<hostname>-<YYYYMMDDTHHMMSSZ>/audit.json` and redacted raw output beside it.

Tell the person to open `viewer/index.html` in a browser and load that `audit.json` (file picker or drag the file onto the page). The viewer is static. Do not generate a new HTML report.

## Summarize

Read `audit.json` and summarize in this order:

1. Read-only verification (`verification.ok`). If it is false, say so first and stop.
2. Overall posture and the gap rows in `matrix`.
3. Trusted projects, including whether the home directory is trusted.
4. Auto-allow rules whose risk is gap or warn.
5. MCP servers, plugins, and high-privilege feature flags.
6. The highest-priority items in `recommendations`, naming each item's `source` (kit matrix, tool, or heuristic).
7. What was skipped or not covered.

State that you did not change configuration.
