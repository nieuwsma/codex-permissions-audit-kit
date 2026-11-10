# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""The shell runner against a fake HOME, plus shellcheck."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "full-readonly-audit.sh"
TOKEN = "ghp_FAKESYNTHETICGITHUBTOKENVALUE123456"
AUTH_SECRET = "SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK"

CODEX = """#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  printf '%s\\n' "codex-cli 0.0.0-fixture"
  exit 0
fi
if [ "${1:-}" = "doctor" ] && [ "${2:-}" = "--json" ]; then
  printf '%s\\n' '{"fixture":true}'
  exit 0
fi
printf '%s\\n' "fixture: $*"
exit 0
"""

TAMPER = """#!/bin/sh
printf '\\n# tampered by fixture\\n' >> "$HOME/.codex/config.toml"
printf '%s\\n' "tampered"
exit 0
"""


def _write_home(home: Path) -> None:
    codex = home / ".codex"
    (codex / "rules").mkdir(parents=True)
    (home / ".config" / "opencode").mkdir(parents=True)
    (codex / "config.toml").write_text(
        f"""
approval_policy = "never"
sandbox_mode = "danger-full-access"
default_permissions = ":danger-full-access"
[projects."{home.as_posix()}"]
trust_level = "trusted"
[mcp_servers.github]
url = "https://example.invalid/mcp/"
default_tools_approval_mode = "auto"
[mcp_servers.github.env]
GITHUB_TOKEN = "{TOKEN}"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (codex / "rules" / "default.rules").write_text(
        'prefix_rule(pattern = ["git", "push"], decision = "allow")\n'
        'prefix_rule(pattern = ["rm", ["-rf"]], decision = "allow")\n',
        encoding="utf-8",
    )
    (codex / "auth.json").write_text('{"access_token":"%s"}\n' % AUTH_SECRET, encoding="utf-8")
    (home / ".config" / "opencode" / "opencode.json").write_text('{"share":"manual"}\n', encoding="utf-8")


def _run(home: Path, report: Path, bindir: Path) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "TMPDIR": str(report.parent),
    }
    return subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--home",
            str(home),
            "--report-dir",
            str(report),
            "--hostname",
            "fixture-host",
            "--generated-at",
            "2026-04-02T15:04:00Z",
        ],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class RunnerTests(unittest.TestCase):
    def test_shellcheck(self) -> None:
        if shutil.which("shellcheck") is None:
            self.skipTest("shellcheck is not installed")
        result = subprocess.run(
            ["shellcheck", str(SCRIPT), str(ROOT / "scripts" / "local-audit.sh")],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_script_does_not_invoke_mutating_commands(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotRegex(stripped, r"\bmcp-audit\s+(fix|lock|pin|register|push-nucleus)\b")
            self.assertNotIn("--connect", stripped)
            self.assertNotRegex(stripped, r"^\s*sudo\b")

    def test_fake_home_is_unchanged_and_redacted(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            report = root / "report"
            bindir = root / "bin"
            bindir.mkdir()
            home.mkdir()
            _write_home(home)
            codex = bindir / "codex"
            codex.write_text(CODEX, encoding="utf-8")
            codex.chmod(codex.stat().st_mode | stat.S_IEXEC)
            before = (home / ".codex" / "config.toml").read_bytes()
            auth_stat = (home / ".codex" / "auth.json").stat()
            result = _run(home, report, bindir)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual((home / ".codex" / "config.toml").read_bytes(), before)
            after_auth = (home / ".codex" / "auth.json").stat()
            self.assertEqual(after_auth.st_size, auth_stat.st_size)
            self.assertEqual(after_auth.st_mtime_ns, auth_stat.st_mtime_ns)
            self.assertIn(str(report / "report.html"), result.stdout)
            document = json.loads((report / "audit.json").read_text(encoding="utf-8"))
            page = (report / "report.html").read_text(encoding="utf-8")
            self.assertIn('id="audit-data"', page)
            self.assertIn("fixture-host", page)
            self.assertNotIn(TOKEN, page)
            self.assertTrue(document["verification"]["ok"])
            self.assertEqual(document["summary"]["posture"], "gap")
            self.assertTrue((report / "raw" / "codex-version.out").is_file())
            self.assertEqual(document["tools"]["mcp_audit"]["status"], "skipped")
            self.assertEqual(document["tools"]["access_auditor"]["status"], "skipped")
            self.assertEqual(document["tools"]["aisec_codex_audit"]["status"], "skipped")
            auth_watch = next(item for item in document["verification"]["watched"] if item["id"] == "codex-auth")
            self.assertFalse(auth_watch["content_read"])
            blob = b"".join(path.read_bytes() for path in report.rglob("*") if path.is_file())
            self.assertNotIn(TOKEN.encode(), blob)
            self.assertNotIn(AUTH_SECRET.encode(), blob)
            self.assertFalse(list(report.rglob("auth.json")))

    def test_tamper_fails_verification(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            report = root / "report"
            bindir = root / "bin"
            bindir.mkdir()
            home.mkdir()
            _write_home(home)
            codex = bindir / "codex"
            codex.write_text(TAMPER, encoding="utf-8")
            codex.chmod(codex.stat().st_mode | stat.S_IEXEC)
            result = _run(home, report, bindir)
            self.assertEqual(result.returncode, 3, result.stderr + result.stdout)
            self.assertIn("READ-ONLY VERIFICATION FAILED", result.stderr)
            document = json.loads((report / "audit.json").read_text(encoding="utf-8"))
            self.assertTrue((report / "report.html").is_file())
            self.assertFalse(document["verification"]["ok"])
            blob = b"".join(path.read_bytes() for path in report.rglob("*") if path.is_file())
            self.assertNotIn(TOKEN.encode(), blob)
            self.assertNotIn(AUTH_SECRET.encode(), blob)


if __name__ == "__main__":
    unittest.main()
