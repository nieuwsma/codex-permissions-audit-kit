# audit.json

`scripts/full-readonly-audit.sh` writes `reports/<hostname>-<YYYYMMDDTHHMMSSZ>/audit.json`. The shape is `schema/audit.schema.json` (JSON Schema draft 2020-12). `examples/fixtures/audit.example.json` is a synthetic file the viewer can open. It is not from a real machine.

`schema_version` is `1.0.0`.

## Top level

| Field | What it is |
| --- | --- |
| `generated_at` | UTC timestamp of the run. |
| `host` | Hostname and OS. The username is not a separate field. |
| `kit.pins` | Pinned third-party versions from `scripts/auditkit/pins.py`. |
| `invocation.flags` | Which optional scanners were requested. |
| `summary` | Posture (`ok`, `warn`, or `gap`), headline, matrix counts, and which tools ran. |
| `codex` | CLI command results, effective posture, trusted projects, MCP servers, plugins, feature flags, and OpenTelemetry settings. |
| `rules` | Parsed `prefix_rule` entries and any prefix rules found in managed requirements. Starlark is not executed. |
| `requirements` | `/etc/codex/requirements.toml` and, on macOS, the `com.openai.codex` MDM payload. The base64 blob is not stored. |
| `opencode` | `share`, short permission values, and MCP server names. |
| `tools` | `local_audit`, `codex_cli`, `mcp_audit`, `access_auditor`, and `aisec_codex_audit`. Each has `status` (`ok`, `skipped`, or `error`), a reason, findings, and that tool's recommendations. |
| `matrix` | One row per kit-matrix rule. `status` is `ok`, `warn`, `gap`, `info`, or `skipped`. `source` is `kit-matrix`. |
| `recommendations` | Prioritized advice. `source` is `kit-matrix`, `tool`, or `heuristic`. See `docs/recommendation-rules.md`. |
| `skipped` | Steps and matrix checks that did not run, with the reason. |
| `not_covered` | Things the audit refuses to do, including TCC prompts, sudo, and reading `auth.json`. |
| `verification` | Before/after snapshot. `ok` is false when a watched file changed. `auth.json` entries use size and mtime only, with `content_read: false`. |
| `redaction.replacements` | How many secret-shaped strings were masked before the report was written. |

Raw scanner output, already redacted, sits next to `audit.json` under `raw/`. Paths inside the JSON point at those files. `auth.json` is never copied.

Open `viewer/index.html` and load `audit.json`. The viewer only renders this document. It does not generate a new report and it does not change configuration.
