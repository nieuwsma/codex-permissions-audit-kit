# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Redaction covers token shapes and secret-named fields."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from auditkit.redact import redact_bytes, redact_obj, redact_text  # noqa: E402


class RedactTests(unittest.TestCase):
    def test_github_and_openai_tokens_are_masked(self) -> None:
        text = 'token = "ghp_FAKESYNTHETICGITHUBTOKENVALUE123456" and sk-proj-abcdefghijklmnopqrstuvwxyz'
        cleaned, count = redact_text(text)
        self.assertGreaterEqual(count, 2)
        self.assertNotIn("ghp_FAKESYNTHETICGITHUBTOKENVALUE123456", cleaned)
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz", cleaned)
        self.assertIn("[REDACTED", cleaned)

    def test_named_secret_in_json(self) -> None:
        payload = {"access_token": "SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK", "share": "manual"}
        cleaned, count = redact_obj(payload)
        self.assertGreaterEqual(count, 1)
        self.assertEqual(cleaned["access_token"], "[REDACTED]")
        self.assertEqual(cleaned["share"], "manual")
        encoded, _ = redact_bytes(json.dumps(payload).encode())
        self.assertNotIn(b"SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK", encoded)


if __name__ == "__main__":
    unittest.main()
