# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Matrix rules fire on a synthetic weak config and stay quiet on a tight one."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from auditkit.assess import HEURISTIC_IDS, KM_IDS, RULE_IDS, build_heuristics, build_matrix  # noqa: E402
from auditkit.parse_codex import parse_config, parse_opencode, parse_rules_dir  # noqa: E402
from auditkit.parse_tools import parse_access_auditor  # noqa: E402


RULES = """
prefix_rule(
    pattern = ["git", "push"],
    decision = "allow",
    justification = "synthetic allow",
)
prefix_rule(
    pattern = ["curl"],
    decision = "allow",
)
prefix_rule(
    pattern = ["rm", ["-rf", "-r", "-f"]],
    decision = "allow",
)
prefix_rule(
    pattern = ["npm", "install", "-g"],
    decision = "allow",
)
prefix_rule(
    pattern = ["sudo"],
    decision = "allow",
)
prefix_rule(
    pattern = ["git", "status"],
    decision = "allow",
)
prefix_rule(
    pattern = ["rm"],
    decision = "forbidden",
    justification = "Use git clean",
)
"""


def _requirements(present: bool, danger: bool = False) -> dict:
    if not present:
        return {
            "locations": [
                {"id": "etc", "path": "/etc/codex/requirements.toml", "status": "absent", "reason": "", "summary": None},
                {"id": "mdm", "path": "MDM", "status": "skipped", "reason": "not macOS", "summary": None},
            ]
        }
    return {
        "locations": [
            {
                "id": "etc",
                "path": "/etc/codex/requirements.toml",
                "status": "present",
                "reason": "",
                "summary": {
                    "danger_full_access_allowed": danger,
                    "allows_never": False,
                    "prefix_rules": [],
                },
            }
        ]
    }


class AssessTests(unittest.TestCase):
    def test_rule_ids_are_documented(self) -> None:
        doc = (Path(__file__).resolve().parents[1] / "docs" / "recommendation-rules.md").read_text(encoding="utf-8")
        for rule_id in RULE_IDS:
            self.assertIn(f"`{rule_id}`", doc)

    def test_weak_home_is_a_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            codex = home / ".codex"
            (codex / "rules").mkdir(parents=True)
            (codex / "rules" / "default.rules").write_text(RULES, encoding="utf-8")
            (codex / "config.toml").write_text(
                f"""
approval_policy = "never"
sandbox_mode = "danger-full-access"
default_permissions = ":danger-full-access"
approvals_reviewer = "auto_review"
[projects."{home.as_posix()}"]
trust_level = "trusted"
[mcp_servers.github]
url = "https://example.invalid/mcp/"
default_tools_approval_mode = "auto"
[mcp_servers.github.tools.delete_branch]
approval_mode = "auto"
[features]
skill_mcp_dependency_install = true
[otel]
log_user_prompt = true
""".strip()
                + "\n",
                encoding="utf-8",
            )
            opencode = home / ".config" / "opencode"
            opencode.mkdir(parents=True)
            (opencode / "opencode.json").write_text(
                json.dumps({"share": "auto", "permission": {"bash": "allow"}}),
                encoding="utf-8",
            )
            local = {
                "config": parse_config(codex / "config.toml", home),
                "rules": parse_rules_dir(codex / "rules"),
                "requirements": _requirements(False),
                "opencode": parse_opencode(opencode / "opencode.json", home),
            }
            checks, recs = build_matrix(local)
            self.assertEqual([check["id"] for check in checks], KM_IDS)
            by_id = {check["id"]: check["status"] for check in checks}
            self.assertEqual(by_id["KM-APPROVAL"], "gap")
            self.assertEqual(by_id["KM-DANGER-PROFILE"], "gap")
            self.assertEqual(by_id["KM-HOME-TRUSTED"], "gap")
            self.assertEqual(by_id["KM-RULE-GIT-PUSH"], "gap")
            self.assertEqual(by_id["KM-RULE-CURL"], "gap")
            self.assertEqual(by_id["KM-RULE-RM"], "gap")
            self.assertEqual(by_id["KM-RULE-SUDO"], "gap")
            self.assertEqual(by_id["KM-RULE-INSTALLER"], "gap")
            self.assertEqual(by_id["KM-RULE-OTHER-ALLOW"], "ok")
            self.assertEqual(by_id["KM-MCP-APPROVAL"], "gap")
            self.assertEqual(by_id["KM-OPENCODE-SHARE"], "gap")
            self.assertEqual(by_id["KM-REQUIREMENTS"], "warn")
            heuristics = {rec["id"] for rec in build_heuristics(local, auth_present=True)}
            self.assertTrue(set(HEURISTIC_IDS).issubset(heuristics))
            self.assertTrue(any(rec["source"] == "kit-matrix" for rec in recs))
            blob = json.dumps(local)
            self.assertNotIn("ghp_", blob)

    def test_tight_config_has_no_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            codex = home / ".codex"
            codex.mkdir()
            (codex / "config.toml").write_text(
                """
approval_policy = "on-request"
default_permissions = ":workspace"
[projects."/work/demo"]
trust_level = "trusted"
[mcp_servers.context7]
url = "https://example.invalid/context7"
default_tools_approval_mode = "prompt"
[features]
skill_mcp_dependency_install = false
""".strip()
                + "\n",
                encoding="utf-8",
            )
            (codex / "rules").mkdir()
            (codex / "rules" / "default.rules").write_text(
                'prefix_rule(pattern = ["git", "push"], decision = "prompt")\n',
                encoding="utf-8",
            )
            local = {
                "config": parse_config(codex / "config.toml", home),
                "rules": parse_rules_dir(codex / "rules"),
                "requirements": _requirements(True, danger=False),
                "opencode": {"present": False, "share": None, "permissions": {}},
            }
            checks, recs = build_matrix(local)
            self.assertFalse(any(check["status"] == "gap" for check in checks))
            self.assertFalse(any(rec["priority"] == "critical" for rec in recs))
            self.assertEqual(build_heuristics(local, auth_present=False), [])

    def test_access_auditor_secret_keeps_preview_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            (report / "raw").mkdir()
            (report / "raw" / "access-auditor.out").write_text(
                "\n".join(
                    [
                        "[HIGH  ] Codex CLI · Secret in history · 1 secret in a Codex CLI session",
                        "          OpenAI API key: sk-••••ab · last used 2026-04-02 · ~/.codex/sessions/example.jsonl",
                        "",
                        "1 grants found. TCC readable: no",
                    ]
                ),
                encoding="utf-8",
            )
            parsed = parse_access_auditor(
                report,
                {"steps": [{"id": "access-auditor", "status": "ok", "reason": "", "raw": []}]},
            )
            secret = parsed["findings"][0]["secret"]
            self.assertEqual(secret["path"], "~/.codex/sessions/example.jsonl")
            self.assertEqual(secret["type"], "OpenAI API key")
            self.assertEqual(secret["date"], "2026-04-02")
            self.assertIn("••••", secret["preview"])
            self.assertNotIn("detail", parsed["findings"][0]["detail"] or "x")
            self.assertEqual(parsed["findings"][0]["detail"], "")


if __name__ == "__main__":
    unittest.main()
