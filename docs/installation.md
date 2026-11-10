# Installation

The audit entry point is `scripts/full-readonly-audit.sh`. Day-to-day steps, including how to open the viewer, are in the README. Agents should follow `AGENTS.md` and should not change configuration.

## Prerequisites

- bash
- Python 3.11 or newer (`tomllib` parses `config.toml`)
- Codex CLI on `PATH` for the built-in doctor, MCP, plugin, and feature commands

The script refuses to run as root.

## Optional scanners

These run when the binary or checkout is already available. They download or build only with a flag, and the install lands inside the report directory rather than your home directory.

| Tool | Pin | Flag |
| --- | --- | --- |
| mcp-audit-scanner (command `mcp-audit`) | `0.29.0` on PyPI | `--with-mcp-audit` (uses `uv tool install` when `uv` exists, otherwise `pip install --target`) |
| AI Access Auditor | commit `f197f39122a21c1169a4ce77e7bfcf58b83cb0cd` | `--with-access-auditor`, or set `AI_ACCESS_AUDITOR_HOME` to a checkout that contains `server.js`. Requires Node. The runner sets `AUDIT_DATA_DIR` to the report temp directory and runs only `node server.js --scan`. |
| AISecurityLabs Codex Security Audit | commit `2031e5da6a0a086a5fbf1dcc0aea09dc0135b5eb` | `--with-aisec-audit`. Requires Docker and git. |

The Codex Security Audit Dockerfile at that commit pins `yq-go=4.53.3-r1`, which is no longer in Alpine 3.24. The runner rewrites that pin to `yq-go=4.53.3-r2` in the checkout under the report directory, then builds `codex-audit:kit-2031e5da`. It does not modify a checkout outside the report. The container runs with `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, and `--user` set to your uid and gid. A writable tmpfs is mounted at `/tmp` inside the container so the audit script can write its own scratch files. Host mounts are read-only and limited to `config.toml`, `hooks.json`, `rules/`, `AGENTS.md`, shell startup files, `/etc/codex/requirements.toml` when it exists, and the project directory. `auth.json`, history, and session logs are not mounted. Reports are JSON, HTML, and text, saved under the report `raw/` directory.

Commands this kit does not run: `mcp-audit fix`, `lock`, `pin`, `register`, `push-nucleus`, `--connect`, AI Access Auditor revoke or hook install, and anything with sudo.

## Deploying requirements.toml

Managed requirements are still the control you want in an enterprise. The audit only reports whether they are present.

- **Cloud:** ChatGPT admin, Codex Policies, create managed requirements.
- **MDM (macOS):** preference domain `com.openai.codex`, key `requirements_toml_base64`. The audit reads it with `defaults` and does not store the base64 value.
- **File:** `/etc/codex/requirements.toml` (Unix) or `%ProgramData%\OpenAI\Codex\requirements.toml` (Windows). This kit's Unix runner reads the Unix path only.

Precedence (later overrides earlier): system file, then cloud-managed, then MDM.

A starting point is `examples/requirements.toml`. The privilege matrix is `examples/privilege-matrix.md`.

## Tests

```bash
shellcheck scripts/full-readonly-audit.sh scripts/local-audit.sh
python3 -m unittest discover -s tests -v
node tests/test-viewer.mjs
```

The Python tests run the audit script against a fake home directory. They do not install the optional scanners.
