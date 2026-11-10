# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
"""Pinned third-party tools. The runner reads these values at startup."""

PINS = {
    "MCP_AUDIT_VERSION": "0.29.0",
    "ACCESS_AUDITOR_COMMIT": "f197f39122a21c1169a4ce77e7bfcf58b83cb0cd",
    "ACCESS_AUDITOR_REPO": "https://github.com/dirmedmr-alt/ai-access-auditor.git",
    "AISEC_COMMIT": "2031e5da6a0a086a5fbf1dcc0aea09dc0135b5eb",
    "AISEC_REPO": "https://github.com/aisecuritylabs-org/coding-agent-security.git",
    "AISEC_YQ_FROM": "yq-go=4.53.3-r1",
    "AISEC_YQ_TO": "yq-go=4.53.3-r2",
    "AISEC_IMAGE": "codex-audit:kit-2031e5da",
}
