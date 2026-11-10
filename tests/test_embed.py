# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""report.html is the viewer template with audit.json embedded and escaped."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from auditkit.report_html import embed_report  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "viewer" / "index.html").read_text(encoding="utf-8")
FIXTURE = (ROOT / "examples" / "fixtures" / "audit.example.json").read_text(encoding="utf-8")


def _embedded(html: str) -> str:
    match = re.search(
        r'<script type="application/json" id="audit-data">\n([\s\S]*?)\n</script>',
        html,
    )
    if not match:
        raise AssertionError("audit-data block missing")
    return match.group(1)


def _js(html: str) -> str:
    match = re.search(r"<script>\n([\s\S]*?)</script>", html)
    if not match:
        raise AssertionError("viewer script missing")
    return match.group(1)


class EmbedTests(unittest.TestCase):
    def test_fixture_round_trip_keeps_the_viewer_script(self) -> None:
        page = embed_report(TEMPLATE, FIXTURE)
        self.assertEqual(_js(page), _js(TEMPLATE))
        self.assertEqual(json.loads(_embedded(page))["host"]["hostname"], "example-mac")

    def test_script_end_tag_cannot_break_out(self) -> None:
        payload = {
            "summary": {
                "headline": "</script><script>alert(1)</script>",
                "also": "</SCRIPT>",
            }
        }
        raw = json.dumps(payload)
        page = embed_report(TEMPLATE, raw)
        body = _embedded(page)
        self.assertNotIn("</script>", body.lower())
        self.assertEqual(
            json.loads(body)["summary"]["headline"],
            "</script><script>alert(1)</script>",
        )
        self.assertEqual(json.loads(body)["summary"]["also"], "</SCRIPT>")


if __name__ == "__main__":
    unittest.main()
