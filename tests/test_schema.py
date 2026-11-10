# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""The example fixture matches the published shape."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate(schema: dict, data, path: str = "$") -> None:
    if "const" in schema and data != schema["const"]:
        raise AssertionError(f"{path} expected {schema['const']!r}")
    if "enum" in schema and data not in schema["enum"]:
        raise AssertionError(f"{path} value {data!r} not in {schema['enum']}")
    types = schema.get("type")
    if isinstance(types, str):
        types = [types]
    if types:
        type_map = {"object": dict, "array": list, "string": str, "boolean": bool, "integer": int}
        if not any(
            (item == "null" and data is None) or (item in type_map and isinstance(data, type_map[item]))
            for item in types
        ):
            raise AssertionError(f"{path} has type {type(data).__name__}, expected {types}")
    if "properties" in schema and isinstance(data, dict):
        for key in schema.get("required", []):
            if key not in data:
                raise AssertionError(f"{path}.{key} missing")
        for key, value in data.items():
            if key in schema["properties"]:
                validate(schema["properties"][key], value, f"{path}.{key}")
    if schema.get("type") == "array" and isinstance(data, list) and "items" in schema:
        for index, item in enumerate(data):
            validate(schema["items"], item, f"{path}[{index}]")


class SchemaTests(unittest.TestCase):
    def test_example_fixture(self) -> None:
        schema = json.loads((ROOT / "schema" / "audit.schema.json").read_text(encoding="utf-8"))
        document = json.loads((ROOT / "examples" / "fixtures" / "audit.example.json").read_text(encoding="utf-8"))
        validate(schema, document)
        self.assertEqual(document["host"]["hostname"], "example-mac")
        self.assertTrue(document["verification"]["ok"])
        self.assertIn("mcp_audit", document["tools"])
        blob = json.dumps(document)
        self.assertNotIn("ghp_FAKESYNTHETICGITHUBTOKENVALUE123456", blob)
        self.assertNotIn("SUPER_SECRET_AUTH_TOKEN_DO_NOT_LEAK", blob)


if __name__ == "__main__":
    unittest.main()
