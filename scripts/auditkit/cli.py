#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Command line for the read-only audit runner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow `python3 scripts/auditkit/cli.py` without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auditkit.assemble import assemble, dumps  # noqa: E402
from auditkit.pins import PINS  # noqa: E402
from auditkit.redact import redact_bytes  # noqa: E402
from auditkit.snapshot import snapshot  # noqa: E402


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def cmd_pin(args: argparse.Namespace) -> int:
    if args.name not in PINS:
        print(f"Unknown pin {args.name}", file=sys.stderr)
        return 2
    print(PINS[args.name])
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    payload = snapshot(Path(args.home), Path(args.codex_home), Path(args.xdg_config))
    _save(Path(args.out), payload)
    return 0


def cmd_redact_file(args: argparse.Namespace) -> int:
    src = Path(args.src)
    dest = Path(args.dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    body, count = redact_bytes(src.read_bytes())
    dest.write_bytes(body)
    print(count)
    return 0


def cmd_meta_init(args: argparse.Namespace) -> int:
    payload = {
        "hostname": args.hostname,
        "generated_at": args.generated_at,
        "flags": {
            "with_mcp_audit": args.with_mcp_audit == "1",
            "with_access_auditor": args.with_access_auditor == "1",
            "with_aisec_audit": args.with_aisec_audit == "1",
        },
        "yq_patched": False,
        "redaction_replacements": 0,
        "access_auditor_commit": "",
        "aisec_commit": "",
        "steps": [],
    }
    _save(Path(args.out), payload)
    return 0


def cmd_meta_set(args: argparse.Namespace) -> int:
    path = Path(args.meta)
    payload = _load(path)
    if args.key in {"yq_patched"}:
        payload[args.key] = args.value == "1"
    elif args.key in {"redaction_replacements"}:
        payload[args.key] = int(args.value)
    elif args.key in {"access_auditor_commit", "aisec_commit", "hostname", "generated_at"}:
        payload[args.key] = args.value
    else:
        print(f"Unknown meta key {args.key}", file=sys.stderr)
        return 2
    _save(path, payload)
    return 0


def cmd_add_step(args: argparse.Namespace) -> int:
    path = Path(args.meta)
    payload = _load(path)
    exit_code = None
    if args.exit_code != "":
        exit_code = int(args.exit_code)
    payload["steps"] = [step for step in payload.get("steps", []) if step.get("id") != args.id]
    payload["steps"].append(
        {
            "id": args.id,
            "status": args.status,
            "reason": args.reason,
            "exit_code": exit_code,
            "raw": args.raw or [],
        }
    )
    _save(path, payload)
    return 0


def cmd_assemble(args: argparse.Namespace) -> int:
    home = Path(args.home)
    codex_home = Path(args.codex_home)
    xdg = Path(args.xdg_config)
    report = Path(args.report)
    document = assemble(
        home,
        codex_home,
        xdg,
        report,
        _load(Path(args.before)),
        _load(Path(args.after)),
        _load(Path(args.meta)),
    )
    out = Path(args.out)
    out.write_text(dumps(document), encoding="utf-8")
    if not document["verification"]["ok"]:
        print("READ-ONLY VERIFICATION FAILED", file=sys.stderr)
        for item in document["verification"]["watched"]:
            if item["changed"]:
                print(f"  changed: {item['path']}", file=sys.stderr)
        print(f"Wrote {out}", file=sys.stderr)
        return 3
    return 0


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_example(dest: Path) -> dict:
    """Synthetic audit used by the checked-in viewer fixture. No live machine data."""
    import tempfile

    from auditkit.snapshot import snapshot as take_snapshot

    with tempfile.TemporaryDirectory(prefix="audit-example-") as tmp:
        root = Path(tmp)
        home = root / "home"
        codex = home / ".codex"
        xdg = home / ".config"
        report = root / "report"
        token = "ghp_" + "FAKESYNTHETICGITHUBTOKENVALUE123456"
        (codex / "rules").mkdir(parents=True)
        (xdg / "opencode").mkdir(parents=True)
        config = f"""approval_policy = "never"
sandbox_mode = "danger-full-access"
default_permissions = ":danger-full-access"
approvals_reviewer = "auto_review"

[projects."{home.as_posix()}"]
trust_level = "trusted"

[projects."{home.as_posix()}/src/demo"]
trust_level = "trusted"

[mcp_servers.github]
url = "https://example.invalid/mcp/"
default_tools_approval_mode = "auto"

[mcp_servers.github.env]
GITHUB_TOKEN = "{token}"

[mcp_servers.github.tools.delete_branch]
approval_mode = "auto"

[mcp_servers.localfs]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/"]

[plugins."demo@local"]
enabled = true

[features]
skill_mcp_dependency_install = true

[otel]
log_user_prompt = true
exporter = "otlp-http"
"""
        _write(codex / "config.toml", config)
        _write(
            codex / "rules" / "default.rules",
            """prefix_rule(
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
""",
        )
        _write(
            codex / "auth.json",
            '{"access_token":"SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK"}\n',
        )
        _write(
            xdg / "opencode" / "opencode.json",
            json.dumps(
                {
                    "share": "auto",
                    "permission": {"bash": "allow", "edit": "ask"},
                    "mcp": {"docs": {"command": "echo"}},
                }
            ),
        )
        raw = report / "raw"
        raw.mkdir(parents=True)
        _write(raw / "codex-version.out", "codex-cli 0.0.0-example\n")
        _write(raw / "local-audit.out", "example local audit\n")
        _write(
            raw / "mcp-version.out",
            "mcp-audit 0.29.0\n",
        )
        _write(
            raw / "mcp-discover.out",
            json.dumps([{"client": "codex", "path": "~/.codex/config.toml"}]),
        )
        _write(
            raw / "mcp-scan.out",
            json.dumps(
                {
                    "version": "0.29.0",
                    "score": {"numeric": 40, "grade": "D"},
                    "findings": [
                        {
                            "id": "SYN-001",
                            "severity": "HIGH",
                            "title": "Synthetic high finding",
                            "description": "Example only. This finding is not from a real machine.",
                            "remediation": "Set the GitHub MCP server approval mode to prompt.",
                            "server": "github",
                            "finding_path": "~/.codex/config.toml",
                        }
                    ],
                }
            ),
        )
        _write(
            raw / "mcp-reach.out",
            json.dumps(
                {
                    "agents": [
                        {
                            "name": "Codex",
                            "verdict": "not_safe_to_allow",
                            "reasons": [
                                {
                                    "text": "sandbox_mode is danger-full-access and approval_policy is never."
                                }
                            ],
                        }
                    ]
                }
            ),
        )
        _write(
            raw / "access-auditor.out",
            "\n".join(
                [
                    "[HIGH  ] Codex CLI · Secret in history · 1 secret in a Codex CLI session",
                    "          OpenAI API key: sk-••••ab · last used 2026-04-02 · ~/.codex/sessions/example.jsonl",
                    "[HIGH  ] Codex CLI · Permission mode · approval_policy = never",
                    "          Runs commands without ever asking",
                    "",
                    "2 grants found. TCC readable: no",
                    "",
                ]
            ),
        )
        _write(
            raw / "aisec.json",
            json.dumps(
                {
                    "tool": "codex-audit",
                    "version": "1.0.0",
                    "summary": {"pass": 1, "warn": 1, "fail": 1, "info": 0},
                    "checks": [
                        {
                            "id": "SYN-FAIL",
                            "status": "FAIL",
                            "title": "approval_policy = never",
                            "detail": "Synthetic example.",
                            "why": "Codex will not ask before running commands.",
                            "guide_step": 4,
                        },
                        {
                            "id": "SYN-WARN",
                            "status": "WARN",
                            "title": "Login shells are allowed",
                            "detail": "Synthetic example.",
                            "why": "Shell startup files can export secrets.",
                            "guide_step": 2,
                        },
                        {
                            "id": "SYN-PASS",
                            "status": "PASS",
                            "title": "Example passing check",
                            "detail": "",
                            "why": "",
                            "guide_step": 2,
                        },
                    ],
                }
            ),
        )
        meta = {
            "hostname": "example-mac",
            "generated_at": "2026-04-02T15:00:00Z",
            "flags": {
                "with_mcp_audit": False,
                "with_access_auditor": False,
                "with_aisec_audit": False,
            },
            "yq_patched": False,
            "redaction_replacements": 0,
            "access_auditor_commit": PINS["ACCESS_AUDITOR_COMMIT"],
            "aisec_commit": PINS["AISEC_COMMIT"],
            "steps": [
                {
                    "id": "local-audit",
                    "status": "ok",
                    "reason": "Synthetic example output. Not a live scan of this machine.",
                    "exit_code": 0,
                    "raw": ["raw/local-audit.out"],
                },
                {
                    "id": "codex-cli",
                    "status": "ok",
                    "reason": "Synthetic example output. Not a live scan of this machine.",
                    "exit_code": 0,
                    "raw": ["raw/codex-version.out"],
                },
                {
                    "id": "mcp-audit",
                    "status": "ok",
                    "reason": "Synthetic example output. Not a live scan of this machine.",
                    "exit_code": 0,
                    "raw": ["raw/mcp-scan.out", "raw/mcp-discover.out", "raw/mcp-reach.out"],
                },
                {
                    "id": "access-auditor",
                    "status": "ok",
                    "reason": "Synthetic example output. Not a live scan of this machine.",
                    "exit_code": 0,
                    "raw": ["raw/access-auditor.out"],
                },
                {
                    "id": "aisec-codex-audit",
                    "status": "ok",
                    "reason": "Synthetic example output. Not a live scan of this machine.",
                    "exit_code": 0,
                    "raw": ["raw/aisec.json"],
                },
                {
                    "id": "mdm",
                    "status": "skipped",
                    "reason": "defaults is only used on macOS for the com.openai.codex MDM payload.",
                    "exit_code": None,
                    "raw": [],
                },
            ],
        }
        before = take_snapshot(home, codex, xdg)
        after = take_snapshot(home, codex, xdg)
        document = assemble(home, codex, xdg, report, before, after, meta)
        document["host"]["os"] = "darwin"
        document["host"]["platform"] = "synthetic"
        encoded = dumps(document).replace(home.as_posix(), "/home/example")
        if token in encoded or "SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK" in encoded:
            raise SystemExit("example fixture leaked a synthetic secret")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(encoded, encoding="utf-8")
        return json.loads(encoded)


def cmd_example(args: argparse.Namespace) -> int:
    build_example(Path(args.out))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Codex permissions audit helpers.")
    sub = parser.add_subparsers(dest="command", required=True)

    pin = sub.add_parser("pin")
    pin.add_argument("name")
    pin.set_defaults(func=cmd_pin)

    snap = sub.add_parser("snapshot")
    snap.add_argument("--home", required=True)
    snap.add_argument("--codex-home", required=True)
    snap.add_argument("--xdg-config", required=True)
    snap.add_argument("--out", required=True)
    snap.set_defaults(func=cmd_snapshot)

    red = sub.add_parser("redact-file")
    red.add_argument("--src", required=True)
    red.add_argument("--dest", required=True)
    red.set_defaults(func=cmd_redact_file)

    meta = sub.add_parser("meta-init")
    meta.add_argument("--out", required=True)
    meta.add_argument("--hostname", required=True)
    meta.add_argument("--generated-at", required=True)
    meta.add_argument("--with-mcp-audit", required=True)
    meta.add_argument("--with-access-auditor", required=True)
    meta.add_argument("--with-aisec-audit", required=True)
    meta.set_defaults(func=cmd_meta_init)

    setter = sub.add_parser("meta-set")
    setter.add_argument("--meta", required=True)
    setter.add_argument("--key", required=True)
    setter.add_argument("--value", required=True)
    setter.set_defaults(func=cmd_meta_set)

    step = sub.add_parser("add-step")
    step.add_argument("--meta", required=True)
    step.add_argument("--id", required=True)
    step.add_argument("--status", required=True)
    step.add_argument("--exit-code", default="")
    step.add_argument("--reason", default="")
    step.add_argument("--raw", action="append")
    step.set_defaults(func=cmd_add_step)

    done = sub.add_parser("assemble")
    done.add_argument("--home", required=True)
    done.add_argument("--codex-home", required=True)
    done.add_argument("--xdg-config", required=True)
    done.add_argument("--report", required=True)
    done.add_argument("--before", required=True)
    done.add_argument("--after", required=True)
    done.add_argument("--meta", required=True)
    done.add_argument("--out", required=True)
    done.set_defaults(func=cmd_assemble)

    example = sub.add_parser("example")
    example.add_argument("--out", required=True)
    example.set_defaults(func=cmd_example)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
