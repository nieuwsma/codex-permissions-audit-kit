# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Mask secret-shaped text before it is written to a report."""

from __future__ import annotations

import json
import re
from typing import Any

# Keys whose string values are always masked, even when the value is short.
_SECRET_KEY = re.compile(
    r"(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"secret|password|passwd|authorization|credential|bearer|"
    r"private[_-]?key|session[_-]?token|client[_-]?secret)",
    re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    (
        re.compile(r"\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b"),
        "[REDACTED_API_KEY]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_KEY]",
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
        "[REDACTED_GOOGLE_KEY]",
    ),
    (
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        "[REDACTED_SLACK_TOKEN]",
    ),
    (
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{10,}\b"),
        "[REDACTED_STRIPE_KEY]",
    ),
    (
        re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
        "[REDACTED_NPM_TOKEN]",
    ),
    (
        re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        "[REDACTED_HF_TOKEN]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]{8,}"),
        r"\1 [REDACTED]",
    ),
    (
        re.compile(r"//[^/\s:]+:[^/\s@]+@"),
        "//[REDACTED]@",
    ),
    (
        re.compile(
            r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
            r"id[_-]?token|secret|password|passwd|authorization|client_secret|"
            r"bearer)[\"']?\s*[:=]\s*[\"'])([^\"']{6,})([\"'])"
        ),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(
            r"(?i)([\"']?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|"
            r"secret|password|passwd|authorization)[\"']?\s*[:=]\s*)"
            r"([A-Za-z0-9_\-./+]{8,})"
        ),
        r"\1[REDACTED]",
    ),
]


def redact_text(text: str) -> tuple[str, int]:
    """Return text with secret-shaped substrings replaced, and a replacement count."""
    count = 0
    out = text
    for pattern, repl in _PATTERNS:
        out, n = pattern.subn(repl, out)
        count += n
    return out, count


def redact_obj(value: Any) -> tuple[Any, int]:
    """Recursively mask secret-keyed strings and secret-shaped text."""
    count = 0
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_KEY.search(key) and isinstance(item, str):
                cleaned[key] = "[REDACTED]"
                count += 1
                continue
            child, n = redact_obj(item)
            cleaned[key] = child
            count += n
        return cleaned, count
    if isinstance(value, list):
        items = []
        for item in value:
            child, n = redact_obj(item)
            items.append(child)
            count += n
        return items, count
    if isinstance(value, str):
        redacted, n = redact_text(value)
        return redacted, n
    return value, 0


def redact_bytes(data: bytes) -> tuple[bytes, int]:
    """Redact a file body. JSON objects are walked; other text is scanned."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        text, count = redact_text(data.decode("utf-8", errors="replace"))
        return text.encode("utf-8"), count
    cleaned, count = redact_obj(parsed)
    encoded = json.dumps(cleaned, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    # A second pass catches tokens nested in otherwise ordinary strings.
    text, extra = redact_text(encoded.decode("utf-8"))
    return text.encode("utf-8"), count + extra
