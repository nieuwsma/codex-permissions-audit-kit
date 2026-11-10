# Codex Permissions Audit Kit

This kit is a read-only audit of what Codex and the AI tools beside it can access on a Mac. It reads Codex settings, command rules, MCP servers, plugins, and feature flags, then compares that picture with the privilege matrix in this repository and writes recommendations. The audit never changes anything: it does not edit configuration, change approvals, install hooks, or revoke access.

## Run it with Codex

Clone the repository and start Codex in that directory:

```bash
git clone https://github.com/nieuwsma/codex-permissions-audit-kit.git
cd codex-permissions-audit-kit
codex
```

Paste this prompt:

```text
Run the full read-only audit per AGENTS.md and summarize
```

Codex follows `AGENTS.md`: it runs the audit, does not apply fixes, and summarizes the result. The script writes a directory:

```text
reports/<hostname>-<YYYYMMDDTHHMMSSZ>/audit.json
reports/<hostname>-<YYYYMMDDTHHMMSSZ>/report.html
```

Redacted raw output from each check is in that directory under `raw/`. The script prints the `report.html` path when it finishes.

Open `report.html` in a browser. The audit is already inside the page, so it renders immediately from `file://` with no file picker and no server. `viewer/index.html` is the template that page is copied from. Use the template’s file picker or drag-and-drop only when you want to load a different `audit.json`. If you serve a directory over HTTP, the viewer also loads `./audit.json` when that file is present, and `?data=` still loads an explicit path.

A synthetic `audit.json` for trying the template is `examples/fixtures/audit.example.json`. It is not from a real machine.

## Manual run

Prerequisites:

- bash (the script works with the bash 3.2 that ships with macOS)
- Python 3.11 or newer
- The Codex CLI on `PATH` if you want `codex doctor`, `codex mcp list`, plugin and feature lists, and `scripts/local-audit.sh`. Those steps are skipped when `codex` is missing.

```bash
bash scripts/full-readonly-audit.sh
```

Flags:

| Flag | What it does |
| --- | --- |
| `--home PATH` | Home directory to read. Default is `$HOME`. |
| `--report-dir PATH` | Where to write the report. Default is `reports/<hostname>-<UTC time>/`. |
| `--project PATH` | Directory mounted read-only into the Docker audit. Default is this repository. `$HOME` and `/` are never mounted. |
| `--with-mcp-audit` | If `mcp-audit` is not already on `PATH`, install `mcp-audit-scanner==0.29.0` into the report directory and run discover, check, scan, and reach. |
| `--with-access-auditor` | Clone AI Access Auditor at `f197f39122a21c1169a4ce77e7bfcf58b83cb0cd` into the report directory and run `node server.js --scan`. |
| `--with-aisec-audit` | Clone the AISecurityLabs Codex Security Audit at `2031e5da6a0a086a5fbf1dcc0aea09dc0135b5eb`, build it, and run it. |
| `--hostname NAME` | Hostname stored in `audit.json`. |
| `--generated-at ISO-8601` | Timestamp stored in `audit.json`. |
| `--open` | After the report is written, open `report.html` with `open` on macOS or `xdg-open` on Linux. Off unless you pass this flag. |

Optional tools run when they are already available, and they are skipped with a reason when they are not. Downloading them or building the Docker image happens only with the flags above. `AI_ACCESS_AUDITOR_HOME` can point at an existing checkout that contains `server.js`. The same script runs on Linux; the macOS MDM lookup and TCC are skipped there. More detail is in `docs/installation.md`.

Pinned versions live in `scripts/auditkit/pins.py`:

- mcp-audit-scanner `0.29.0`
- AI Access Auditor `f197f39122a21c1169a4ce77e7bfcf58b83cb0cd`
- Codex Security Audit `2031e5da6a0a086a5fbf1dcc0aea09dc0135b5eb` (the runner rewrites the vanished Alpine pin `yq-go=4.53.3-r1` to `yq-go=4.53.3-r2` inside the report checkout before the image build)

## What it checks

- Codex approval policy, sandbox mode, and `default_permissions`, including whether both legacy and profile settings are set
- Trusted projects, and whether the home directory itself is trusted
- `prefix_rule` entries under `~/.codex/rules/`, especially auto-allow rules for `git push`, `curl` / `wget`, `rm`, `sudo`, and package installers
- MCP servers and their approval modes, plus enabled plugins
- High-privilege feature flags and OpenTelemetry prompt or response export
- Managed requirements at `/etc/codex/requirements.toml` and, on macOS, the `com.openai.codex` MDM payload
- OpenCode `share` and shell permission in `~/.config/opencode/opencode.json`
- When the tools are available: `codex doctor`, `mcp-audit` discover / check / scan / reach, AI Access Auditor `--scan`, and the AISecurityLabs Codex Security Audit (JSON, HTML, and text)

Findings are compared with `examples/privilege-matrix.md` and the sample `examples/requirements.toml`. The rules that turn those findings into recommendations are in `docs/recommendation-rules.md`. The JSON shape is in `docs/audit-json.md` and `schema/audit.schema.json`.

## Read-only and redaction guarantees

The runner writes only under the report directory (its `tmp/` and `raw/` included). It does not use sudo. It does not prompt for Full Disk Access or any other TCC permission. It does not use the network except when you pass a flag that installs a tool or builds the audit image.

Before any scanner runs, and again after, it records:

- a SHA-256 of `~/.codex/config.toml`
- a SHA-256 of each file under `~/.codex/rules/`
- a SHA-256 of `~/.config/opencode/opencode.json` (or the `XDG_CONFIG_HOME` path)
- a SHA-256 of `~/.codex/hooks.json`, so a hook install is visible
- the size and mtime of `~/.codex/auth.json`

`auth.json` is never opened. If any watched file changed, `verification.ok` is false, the report still explains the mismatch, and the script exits 3.

Secret-shaped values are masked before they are written. That includes common token prefixes, private keys, bearer values, and assignments whose names look like keys or passwords. AI Access Auditor secret findings keep only the path, type, date, and a masked preview. Tool state that would otherwise land in `~/.config` is redirected into the report directory. The commands that mutate configuration (`fix`, `lock`, `pin`, `register`, `push-nucleus`, `--connect`, revoke, hook install) are not run.

Do not commit `reports/`. Paths and posture in a report are still private.

## License

Copyright 2026 Nieuwsma Services LLC.

Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.

The optional scanners named above are not included in this repository and are not relicensed by it. They keep their own licenses and are downloaded only when you pass the matching flag.
