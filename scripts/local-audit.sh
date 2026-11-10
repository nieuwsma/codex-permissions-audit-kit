#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
# Codex doctor and MCP list only. The full read-only audit is
# scripts/full-readonly-audit.sh. This script does not change configuration.
# Usage: ./scripts/local-audit.sh

set -euo pipefail

echo "=== Codex doctor (effective config & requirements) ==="
codex doctor || true

echo
echo "=== Active MCP servers ==="
codex mcp list || true

echo
echo "=== Suggested next steps ==="
echo "1. Install mcp-audit: pip install mcp-audit-scanner && mcp-audit scan"
echo "2. Review examples/requirements.toml and privilege-matrix.md"
echo "3. Check ~/.codex/config.toml for approval_policy, default_permissions, mcp_servers"
echo "4. Ensure :danger-full-access is not selected and MCP tools use least privilege"
