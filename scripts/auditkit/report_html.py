# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Copy viewer/index.html and embed an already-redacted audit.json.

The viewer file stays the only rendering template. This module inserts the
JSON into the empty <script type="application/json" id="audit-data"> slot.
"""

from __future__ import annotations

import json
from pathlib import Path

_SLOT = '<script type="application/json" id="audit-data"></script>'


def escape_json_for_script(text: str) -> str:
    """Keep JSON valid while stopping the HTML parser from closing the script tag.

    A raw ``<`` in the payload would let ``</script>`` (any case) end the
    element early. ``\\u003c`` is a JSON escape, so JSON.parse restores ``<``.
    """
    return text.replace("<", r"\u003c").replace("\u2028", r"\u2028").replace("\u2029", r"\u2029")


def embed_report(template: str, audit_text: str) -> str:
    """Return a viewer page with audit_text embedded. audit_text must be JSON."""
    json.loads(audit_text)
    if template.count(_SLOT) != 1:
        raise ValueError("viewer template is missing the audit-data slot")
    escaped = escape_json_for_script(audit_text.strip())
    block = '<script type="application/json" id="audit-data">\n' + escaped + "\n</script>"
    return template.replace(_SLOT, block, 1)


def write_report(template_path: Path, audit_path: Path, dest: Path) -> None:
    html = embed_report(
        template_path.read_text(encoding="utf-8"),
        audit_path.read_text(encoding="utf-8"),
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(html, encoding="utf-8")
