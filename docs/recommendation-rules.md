# Recommendation rules

`scripts/auditkit/assess.py` and `scripts/auditkit/parse_tools.py` turn the audit data into the `matrix` and `recommendations` arrays. The viewer does not invent advice. Each recommendation has a `source`:

| source | Meaning |
| --- | --- |
| `kit-matrix` | Compared with `examples/privilege-matrix.md` and `examples/requirements.toml`. |
| `tool` | Taken from a scanner's own finding text (`mcp-audit`, `ai-access-auditor`, or `aisec-codex-audit`). |
| `heuristic` | A combination the matrix checks do not state on their own. |

A matrix row is `ok`, `warn`, `gap`, `info`, or `skipped`. Rows that are `gap` or `warn` become recommendations. `info` and `ok` stay in the matrix only. Priority for a gap comes from the table below. A warn is always `medium`.

An omitted `decision` on a `prefix_rule` counts as `allow`, which is Codex's default. Read-only prefixes (`git status`, `git diff`, `git log`, `git show`, `ls`, `rg`, `cat`, `pwd`) are `ok`. `forbidden` and `prompt` are `ok`.

## Kit matrix

### `KM-APPROVAL`

Expected: `approval_policy = "on-request"`. `never`, `on-failure`, and `untrusted` are gaps (critical). A missing or granular policy is a warning. The sample requirements allow only `on-request`.

### `KM-DANGER-PROFILE`

Expected: `default_permissions` is `:workspace` or `:read-only`, and `sandbox_mode` is not `danger-full-access`. An active danger-full-access setting is a critical gap. The sample `allowed_permission_profiles` list omits `:danger-full-access`.

### `KM-LEGACY-SANDBOX`

Expected: `sandbox_mode` is unset. Any value is a warning because Codex then uses the legacy sandbox instead of permission profiles.

### `KM-SANDBOX-AND-PROFILE`

Expected: `sandbox_mode` and `default_permissions` are not both set. Both set is a warning.

### `KM-HOME-TRUSTED`

Expected: no project whose path is `$HOME` or `/` has `trust_level = "trusted"`. A trusted home is a critical gap because project `.codex` layers then load for the whole home directory.

### `KM-TRUSTED-PROJECTS`

Informational list of trusted projects that are not the home directory. No recommendation.

### `KM-RULE-GIT-PUSH`

Expected: no `allow` rule whose prefix contains `git` and `push`. A match is a high gap. The sample requirements prompt before `git push`.

### `KM-RULE-GIT-RESET`

Expected: no `allow` rule whose prefix contains `git` plus `reset` or `--hard`. A match is a high gap.

### `KM-RULE-CURL`

Expected: no `allow` rule for `curl` or `wget`. A match is a high gap.

### `KM-RULE-RM`

Expected: no `allow` rule for `rm`. A match is a critical gap. The sample requirements forbid `rm` with `-rf`, `-r`, or `-f`.

### `KM-RULE-SUDO`

Expected: no `allow` rule for `sudo`. A match is a critical gap.

### `KM-RULE-INSTALLER`

Expected: no `allow` rule for `npm`, `pnpm`, `yarn`, `pip`, `pip3`, `brew`, `uv`, or `cargo` together with `install`, `add`, or `-g`. A match is a high gap.

### `KM-RULE-OTHER-ALLOW`

Expected: remaining `allow` rules are read-only prefixes. Anything else, including `bash -c` / `sh -lc`, is a warning.

### `KM-MCP-APPROVAL`

Expected: write-capable MCP servers (filesystem, shell, GitHub, Jira, Linear, databases, and similar) use `prompt`, `writes`, or `approve`. `auto` on those servers, or `auto` on a destructive tool name, is a high gap. `auto` on another server, or a missing mode on a write-capable server, is a warning.

### `KM-FEATURE-INSTALL`

Expected: `skill_mcp_dependency_install` is false or unset, matching the sample requirements. `true` is a warning.

### `KM-FEATURE-HIGH-PRIV`

Expected: features whose names mention computer use, browser use, danger, yolo, bypass, full access, or unsandboxed are not true. A true value is a high gap.

### `KM-OTEL-PROMPTS`

Expected: `otel.log_user_prompt` and `otel.log_agent_responses` are not true. Either one true is a warning, because the export can contain source and credentials. Header values are never copied into the report.

### `KM-REQUIREMENTS`

Expected: a readable managed requirements file at `/etc/codex/requirements.toml` or in the macOS `com.openai.codex` MDM payload. Neither present is a warning. An unreadable file is skipped rather than treated as absent. `sudo` is not used.

### `KM-REQUIREMENTS-PROFILES`

Expected: managed requirements do not allow `:danger-full-access` and do not allow approval `never` or `on-failure`. Allowing either is a critical gap. Skipped when no managed file was readable.

### `KM-OPENCODE-SHARE`

Expected: OpenCode `share` is not `auto`. `auto` is a high gap. A missing `opencode.json` is ok.

### `KM-PLUGINS`

Informational list of enabled plugins. No recommendation.

## Heuristics

### `H-NEVER-AND-DANGER`

Critical when approval is `never` or `on-failure` and a danger-full-access setting is also active.

### `H-HOME-AND-RM`

Critical when the home directory is trusted and an `rm` rule is `allow`.

### `H-AUTH-FILE`

Medium when `auth.json` exists and `cli_auth_credentials_store` is not `keyring`. The file is not opened.

### `H-AUTO-REVIEW`

Medium when `approvals_reviewer` is `auto_review`.

### `H-OPENCODE-SHELL`

Medium when OpenCode `bash` or `shell` permission is `allow`.

## Scanner recommendations

These keep the scanner's own wording. They are not rewritten into the matrix.

- mcp-audit findings at CRITICAL, HIGH, or MEDIUM become recommendations. The detail is the finding's remediation, then its description. Reach verdicts `not_safe_to_allow` (high) and `needs_work` (medium) are included. LOW and INFO stay in the findings list only.
- AI Access Auditor findings at high or medium become recommendations. A secret in history keeps only the path, type, date, and masked preview. The recommendation says to rotate that credential.
- Codex Security Audit checks with status FAIL (high) or WARN (medium) become recommendations. The detail is the check's `why` text, then its detail. PASS and INFO stay in the check list.

The runner never applies these recommendations.
