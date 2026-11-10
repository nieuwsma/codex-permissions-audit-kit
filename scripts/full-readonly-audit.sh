#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nieuwsma Services LLC
# Read-only Codex permissions audit.
# Works with bash 3.2 (the bash that ships with macOS) and newer.
#
# Never invoke: mcp-audit fix, lock, pin, register, or push-nucleus.
# Never pass --connect. Never run node server.js without --scan.
# Never use sudo. Never mount auth.json, history, or session logs.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY=(python3 "$ROOT/scripts/auditkit/cli.py")

usage() {
  cat <<'EOF'
Usage: scripts/full-readonly-audit.sh [options]

Read Codex settings and, where the tools are already available, the optional
scanners. Write reports/<hostname>-<UTC time>/audit.json and report.html.
Do not change configuration. report.html is viewer/index.html with the
redacted audit embedded, so it opens in a browser with no file picker.

Options:
  --home PATH             Home directory to audit (default: $HOME)
  --report-dir PATH       Output directory (default: reports/<host>-<time>)
  --project PATH          Project mounted read-only for the Docker audit
                          (default: this repository). Never $HOME or /.
  --with-mcp-audit        If mcp-audit is missing, install the pinned
                          mcp-audit-scanner into the report directory and run it
  --with-access-auditor   Clone the pinned AI Access Auditor commit into the
                          report directory and run: node server.js --scan
  --with-aisec-audit      Clone the pinned Codex Security Audit commit, patch
                          the vanished yq pin, build the image, and run it
  --hostname NAME         Name recorded in audit.json
  --generated-at ISO-8601 Timestamp recorded in audit.json
  --open                  Open report.html in a browser (macOS open, Linux
                          xdg-open). Off unless you pass this flag.
  -h, --help              Show this help

Already-installed tools run without a flag. A missing tool is skipped.
Downloads, package installs, and docker build run only with the flags above.
AI_ACCESS_AUDITOR_HOME, when set to a checkout that contains server.js, is
used instead of cloning. An existing codex-audit image is not required for
--with-aisec-audit; that flag builds AISEC_IMAGE from the pinned commit.
EOF
}

log() {
  printf '%s\n' "$*" >&2
}

if [ "$(id -u)" -eq 0 ]; then
  log "Refusing to run as root. This audit does not use elevated privileges."
  exit 2
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  log "Python 3.11 or newer is required."
  exit 2
fi

WITH_MCP=0
WITH_ACCESS=0
WITH_AISEC=0
OPEN_REPORT=0
HOME_OVERRIDE=""
REPORT_DIR=""
PROJECT=""
HOSTNAME_OVERRIDE=""
GENERATED_AT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --home)
      HOME_OVERRIDE="${2:-}"
      shift 2
      ;;
    --report-dir)
      REPORT_DIR="${2:-}"
      shift 2
      ;;
    --project)
      PROJECT="${2:-}"
      shift 2
      ;;
    --hostname)
      HOSTNAME_OVERRIDE="${2:-}"
      shift 2
      ;;
    --generated-at)
      GENERATED_AT="${2:-}"
      shift 2
      ;;
    --with-mcp-audit)
      WITH_MCP=1
      shift
      ;;
    --with-access-auditor)
      WITH_ACCESS=1
      shift
      ;;
    --with-aisec-audit)
      WITH_AISEC=1
      shift
      ;;
    --open)
      OPEN_REPORT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "Unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [ -n "$HOME_OVERRIDE" ]; then
  export HOME="$HOME_OVERRIDE"
fi
if [ ! -d "${HOME:-}" ]; then
  log "HOME is not a directory."
  exit 2
fi

CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
XDG_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}"

if [ -z "$HOSTNAME_OVERRIDE" ]; then
  HOSTNAME_OVERRIDE="$(hostname -s 2>/dev/null || hostname)"
fi
HOSTNAME_OVERRIDE="${HOSTNAME_OVERRIDE//[^A-Za-z0-9._-]/_}"
if [ -z "$HOSTNAME_OVERRIDE" ]; then
  HOSTNAME_OVERRIDE="host"
fi

if [ -z "$GENERATED_AT" ]; then
  GENERATED_AT="$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
fi
STAMP="$(python3 -c 'import sys; from datetime import datetime; print(datetime.strptime(sys.argv[1], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y%m%dT%H%M%SZ"))' "$GENERATED_AT")"

if [ -z "$REPORT_DIR" ]; then
  REPORT_DIR="$ROOT/reports/${HOSTNAME_OVERRIDE}-${STAMP}"
fi
mkdir -p "$REPORT_DIR/raw" "$REPORT_DIR/tmp/plain" "$REPORT_DIR/tmp/status" \
  "$REPORT_DIR/tmp/xdg/config" "$REPORT_DIR/tmp/xdg/cache" \
  "$REPORT_DIR/tmp/xdg/data" "$REPORT_DIR/tmp/xdg/state" \
  "$REPORT_DIR/tmp/mcp-cwd" "$REPORT_DIR/tmp/access-auditor-data"

cleanup() {
  if [ -n "${REPORT_DIR:-}" ]; then
    rm -rf "$REPORT_DIR/tmp/plain"
  fi
}
trap cleanup EXIT

META="$REPORT_DIR/tmp/meta.json"
"${PY[@]}" meta-init \
  --out "$META" \
  --hostname "$HOSTNAME_OVERRIDE" \
  --generated-at "$GENERATED_AT" \
  --with-mcp-audit "$WITH_MCP" \
  --with-access-auditor "$WITH_ACCESS" \
  --with-aisec-audit "$WITH_AISEC"

MCP_AUDIT_VERSION="$("${PY[@]}" pin MCP_AUDIT_VERSION)"
ACCESS_AUDITOR_COMMIT="$("${PY[@]}" pin ACCESS_AUDITOR_COMMIT)"
ACCESS_AUDITOR_REPO="$("${PY[@]}" pin ACCESS_AUDITOR_REPO)"
AISEC_COMMIT="$("${PY[@]}" pin AISEC_COMMIT)"
AISEC_REPO="$("${PY[@]}" pin AISEC_REPO)"
AISEC_YQ_FROM="$("${PY[@]}" pin AISEC_YQ_FROM)"
AISEC_YQ_TO="$("${PY[@]}" pin AISEC_YQ_TO)"
AISEC_IMAGE="$("${PY[@]}" pin AISEC_IMAGE)"

REDACTION_COUNT=0

add_step() {
  local id="$1"
  local status="$2"
  local code="$3"
  local reason="$4"
  shift 4
  if [ $# -eq 0 ]; then
    "${PY[@]}" add-step --meta "$META" --id "$id" --status "$status" \
      --exit-code "$code" --reason "$reason"
  else
    local raw_args=()
    local raw
    for raw in "$@"; do
      raw_args+=(--raw "$raw")
    done
    "${PY[@]}" add-step --meta "$META" --id "$id" --status "$status" \
      --exit-code "$code" --reason "$reason" "${raw_args[@]}"
  fi
}

finish_capture() {
  local name="$1"
  local status="$2"
  local dest_out="$3"
  local dest_err="$4"
  local out="$REPORT_DIR/tmp/plain/${name}.out"
  local err="$REPORT_DIR/tmp/plain/${name}.err"
  local count
  local count_err
  count="$("${PY[@]}" redact-file --src "$out" --dest "$REPORT_DIR/raw/${dest_out}")"
  count_err="$("${PY[@]}" redact-file --src "$err" --dest "$REPORT_DIR/raw/${dest_err}")"
  REDACTION_COUNT=$((REDACTION_COUNT + count + count_err))
  rm -f "$out" "$err"
  printf '%s\n' "$status" > "$REPORT_DIR/tmp/status/${name}.code"
}

capture() {
  local name="$1"
  shift
  local out="$REPORT_DIR/tmp/plain/${name}.out"
  local err="$REPORT_DIR/tmp/plain/${name}.err"
  local status=0
  mkdir -p "$REPORT_DIR/tmp/plain" "$REPORT_DIR/raw" "$REPORT_DIR/tmp/status"
  if command -v timeout >/dev/null 2>&1; then
    timeout 120 "$@" >"$out" 2>"$err" || status=$?
  else
    "$@" >"$out" 2>"$err" || status=$?
  fi
  finish_capture "$name" "$status" "${name}.out" "${name}.err"
}

status_of() {
  local name="$1"
  local path="$REPORT_DIR/tmp/status/${name}.code"
  if [ -f "$path" ]; then
    cat "$path"
  else
    printf '%s\n' ""
  fi
}

log "Recording watched files before scanners run"
"${PY[@]}" snapshot \
  --home "$HOME" \
  --codex-home "$CODEX_HOME" \
  --xdg-config "$XDG_CONFIG" \
  --out "$REPORT_DIR/tmp/snapshot-before.json"

run_codex() {
  if ! command -v codex >/dev/null 2>&1; then
    add_step "codex-cli" "skipped" "" "codex is not on PATH."
    add_step "local-audit" "skipped" "" "codex is not on PATH, so scripts/local-audit.sh was not run."
    return 0
  fi
  log "Running codex doctor, mcp list, plugin list, features list, and version"
  capture codex-version codex --version
  capture codex-doctor codex doctor
  capture codex-doctor-json codex doctor --json
  capture codex-doctor-all codex doctor --no-color --all
  capture codex-mcp-list codex mcp list
  capture codex-plugin-list codex plugin list
  capture codex-features-list codex features list
  capture local-audit bash "$ROOT/scripts/local-audit.sh"
  add_step "codex-cli" "ok" "$(status_of codex-version)" "" \
    "raw/codex-version.out" "raw/codex-doctor.out" "raw/codex-doctor-json.out" \
    "raw/codex-doctor-all.out" "raw/codex-mcp-list.out" "raw/codex-plugin-list.out" \
    "raw/codex-features-list.out"
  add_step "local-audit" "ok" "$(status_of local-audit)" "" \
    "raw/local-audit.out" "raw/local-audit.err"
}

run_mcp_one() {
  local name="$1"
  shift
  local out="$REPORT_DIR/tmp/plain/${name}.out"
  local err="$REPORT_DIR/tmp/plain/${name}.err"
  local status=0
  mkdir -p "$REPORT_DIR/tmp/plain"
  (
    cd "$REPORT_DIR/tmp/mcp-cwd" || exit 1
    env \
      XDG_CONFIG_HOME="$REPORT_DIR/tmp/xdg/config" \
      XDG_CACHE_HOME="$REPORT_DIR/tmp/xdg/cache" \
      XDG_DATA_HOME="$REPORT_DIR/tmp/xdg/data" \
      XDG_STATE_HOME="$REPORT_DIR/tmp/xdg/state" \
      "$@"
  ) >"$out" 2>"$err" || status=$?
  finish_capture "$name" "$status" "${name}.out" "${name}.err"
}

install_mcp() {
  local bindir="$REPORT_DIR/tools/bin"
  mkdir -p "$bindir" "$REPORT_DIR/tools/mcp-audit"
  if command -v uv >/dev/null 2>&1; then
    log "Installing mcp-audit-scanner==$MCP_AUDIT_VERSION with uv into the report directory"
    UV_TOOL_DIR="$REPORT_DIR/tools/uv" UV_TOOL_BIN_DIR="$bindir" \
      uv tool install "mcp-audit-scanner==${MCP_AUDIT_VERSION}"
  elif python3 -m pip --version >/dev/null 2>&1; then
    log "Installing mcp-audit-scanner==$MCP_AUDIT_VERSION with pip into the report directory"
    python3 -m pip install --disable-pip-version-check --no-input \
      --target "$REPORT_DIR/tools/mcp-audit" "mcp-audit-scanner==${MCP_AUDIT_VERSION}"
    python3 -c 'from pathlib import Path; import sys
dest = Path(sys.argv[1])
pkg = sys.argv[2]
dest.write_text("#!/usr/bin/env python3\nimport sys\nsys.path.insert(0, %r)\nfrom mcp_audit.cli import app\nraise SystemExit(app())\n" % pkg)
dest.chmod(0o755)
' "$bindir/mcp-audit" "$REPORT_DIR/tools/mcp-audit"
  else
    log "Neither uv nor pip is available."
    return 1
  fi
  export PATH="$bindir:$PATH"
}

run_mcp() {
  if ! command -v mcp-audit >/dev/null 2>&1; then
    if [ "$WITH_MCP" -ne 1 ]; then
      add_step "mcp-audit" "skipped" "" \
        "mcp-audit is not on PATH. Pass --with-mcp-audit to install mcp-audit-scanner==${MCP_AUDIT_VERSION} into the report directory."
      return 0
    fi
    if ! install_mcp; then
      add_step "mcp-audit" "error" "" \
        "Could not install mcp-audit-scanner==${MCP_AUDIT_VERSION} into the report directory."
      return 0
    fi
  fi
  log "Running mcp-audit discover, check, scan, and reach"
  run_mcp_one mcp-version mcp-audit version
  run_mcp_one mcp-discover mcp-audit discover --json
  run_mcp_one mcp-check mcp-audit check --json --no-lock
  run_mcp_one mcp-scan mcp-audit scan --format json --offline --no-lock
  run_mcp_one mcp-reach mcp-audit reach --format json
  local bad=0
  local name
  local code
  for name in mcp-version mcp-discover mcp-check mcp-scan mcp-reach; do
    code="$(status_of "$name")"
    if [ -n "$code" ] && [ "$code" -ge 2 ]; then
      bad=1
    fi
  done
  if [ "$bad" -eq 1 ]; then
    add_step "mcp-audit" "error" "" "One or more mcp-audit commands exited with status 2 or higher. Exit 1 means the scanner found issues and is still recorded." \
      "raw/mcp-version.out" "raw/mcp-discover.out" "raw/mcp-check.out" "raw/mcp-scan.out" "raw/mcp-reach.out"
  else
    add_step "mcp-audit" "ok" "0" "" \
      "raw/mcp-version.out" "raw/mcp-discover.out" "raw/mcp-check.out" "raw/mcp-scan.out" "raw/mcp-reach.out"
  fi
}

clone_pin() {
  local dest="$1"
  local url="$2"
  local commit="$3"
  if ! command -v git >/dev/null 2>&1; then
    log "git is not on PATH."
    return 1
  fi
  rm -rf "$dest"
  mkdir -p "$dest"
  git -C "$dest" init -q
  git -C "$dest" remote add origin "$url"
  git -C "$dest" fetch --depth 1 origin "$commit"
  git -C "$dest" checkout -q --detach FETCH_HEAD
  local got
  got="$(git -C "$dest" rev-parse HEAD)"
  if [ "$got" != "$commit" ]; then
    log "Expected commit $commit but cloned $got"
    return 1
  fi
}

run_access() {
  local dir=""
  if [ -n "${AI_ACCESS_AUDITOR_HOME:-}" ] && [ -f "${AI_ACCESS_AUDITOR_HOME}/server.js" ]; then
    dir="$AI_ACCESS_AUDITOR_HOME"
  elif [ "$WITH_ACCESS" -eq 1 ]; then
    dir="$REPORT_DIR/tools/ai-access-auditor"
    log "Cloning AI Access Auditor $ACCESS_AUDITOR_COMMIT into the report directory"
    if ! clone_pin "$dir" "$ACCESS_AUDITOR_REPO" "$ACCESS_AUDITOR_COMMIT"; then
      add_step "access-auditor" "error" "" "Could not clone AI Access Auditor at the pinned commit."
      return 0
    fi
  else
    add_step "access-auditor" "skipped" "" \
      "AI Access Auditor is not available. Set AI_ACCESS_AUDITOR_HOME to a checkout with server.js, or pass --with-access-auditor to clone ${ACCESS_AUDITOR_COMMIT}."
    return 0
  fi
  if ! command -v node >/dev/null 2>&1; then
    add_step "access-auditor" "error" "" "node is not on PATH, so server.js --scan was not run."
    return 0
  fi
  local observed=""
  if command -v git >/dev/null 2>&1 && git -C "$dir" rev-parse HEAD >/dev/null 2>&1; then
    observed="$(git -C "$dir" rev-parse HEAD)"
    "${PY[@]}" meta-set --meta "$META" --key access_auditor_commit --value "$observed"
  fi
  log "Running AI Access Auditor (node server.js --scan) with AUDIT_DATA_DIR inside the report"
  local out="$REPORT_DIR/tmp/plain/access-auditor.out"
  local err="$REPORT_DIR/tmp/plain/access-auditor.err"
  local status=0
  mkdir -p "$REPORT_DIR/tmp/access-auditor-data"
  if command -v timeout >/dev/null 2>&1; then
    AUDIT_DATA_DIR="$REPORT_DIR/tmp/access-auditor-data" \
      timeout 180 node "$dir/server.js" --scan >"$out" 2>"$err" || status=$?
  else
    AUDIT_DATA_DIR="$REPORT_DIR/tmp/access-auditor-data" \
      node "$dir/server.js" --scan >"$out" 2>"$err" || status=$?
  fi
  finish_capture "access-auditor" "$status" "access-auditor.out" "access-auditor.err"
  if [ "$status" -eq 0 ]; then
    add_step "access-auditor" "ok" "0" "" "raw/access-auditor.out" "raw/access-auditor.err"
  else
    add_step "access-auditor" "error" "$status" "node server.js --scan exited $status." \
      "raw/access-auditor.out" "raw/access-auditor.err"
  fi
}

add_mount() {
  local src="$1"
  local dst="$2"
  if [ ! -e "$src" ]; then
    return 0
  fi
  case "$src" in
    *:*)
      log "Skipping a mount because the path contains a colon: $src"
      ;;
    *)
      MOUNTS+=(-v "$src:$dst:ro")
      ;;
  esac
}

run_aisec() {
  local image_ok=0
  if command -v docker >/dev/null 2>&1 && docker image inspect "$AISEC_IMAGE" >/dev/null 2>&1; then
    image_ok=1
  fi
  if [ "$WITH_AISEC" -ne 1 ] && [ "$image_ok" -ne 1 ]; then
    add_step "aisec-codex-audit" "skipped" "" \
      "The Codex Security Audit image is not built. Pass --with-aisec-audit to clone ${AISEC_COMMIT} and build it. Docker builds are opt-in."
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    add_step "aisec-codex-audit" "error" "" "docker is not on PATH."
    return 0
  fi
  if [ "$WITH_AISEC" -eq 1 ]; then
    local src="$REPORT_DIR/tools/coding-agent-security"
    log "Cloning Codex Security Audit $AISEC_COMMIT into the report directory"
    if ! clone_pin "$src" "$AISEC_REPO" "$AISEC_COMMIT"; then
      add_step "aisec-codex-audit" "error" "" "Could not clone the Codex Security Audit at the pinned commit."
      return 0
    fi
    "${PY[@]}" meta-set --meta "$META" --key aisec_commit --value "$AISEC_COMMIT"
    local patched
    patched="$(python3 -c 'from pathlib import Path; import sys
p = Path(sys.argv[1]); old, new = sys.argv[2], sys.argv[3]
text = p.read_text(); count = text.count(old); p.write_text(text.replace(old, new)); print(count)
' "$src/codex/audit/Dockerfile" "$AISEC_YQ_FROM" "$AISEC_YQ_TO")"
    if [ "$patched" != "0" ]; then
      "${PY[@]}" meta-set --meta "$META" --key yq_patched --value 1
      log "Rewrote Dockerfile pin $AISEC_YQ_FROM to $AISEC_YQ_TO inside the report checkout"
    fi
    log "Building $AISEC_IMAGE"
    if ! docker build -q -f "$src/codex/audit/Dockerfile" -t "$AISEC_IMAGE" "$src" >/dev/null; then
      add_step "aisec-codex-audit" "error" "" "docker build failed for $AISEC_IMAGE."
      return 0
    fi
  fi
  local project="${PROJECT:-$ROOT}"
  local project_real home_real
  project_real="$(cd "$project" && pwd)"
  home_real="$(cd "$HOME" && pwd)"
  MOUNTS=()
  add_mount "$CODEX_HOME/config.toml" "/audit/codex-home/config.toml"
  add_mount "$CODEX_HOME/hooks.json" "/audit/codex-home/hooks.json"
  add_mount "$CODEX_HOME/rules" "/audit/codex-home/rules"
  add_mount "$CODEX_HOME/AGENTS.md" "/audit/codex-home/AGENTS.md"
  add_mount "/etc/codex/requirements.toml" "/audit/requirements.toml"
  local rc
  for rc in .bashrc .zshrc .profile .bash_profile .bash_aliases .zprofile; do
    add_mount "$HOME/$rc" "/audit/rc/$rc"
  done
  local project_name=""
  if [ "$project_real" = "$home_real" ] || [ "$project_real" = "/" ]; then
    log "Not mounting $project_real as the project."
  else
    add_mount "$project_real" "/audit/project"
    project_name="$(basename "$project_real")"
  fi
  local version=""
  if command -v codex >/dev/null 2>&1; then
    version="$(codex --version 2>/dev/null || true)"
  fi
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  run_aisec_format() {
    local fmt="$1"
    local name="$2"
    local dest="$3"
    local out="$REPORT_DIR/tmp/plain/${name}.out"
    local err="$REPORT_DIR/tmp/plain/${name}.err"
    local status=0
    if [ ${#MOUNTS[@]} -eq 0 ]; then
      docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=16m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --pids-limit 256 \
        --memory 256m \
        --user "${uid}:${gid}" \
        -e "CODEX_VERSION=$version" \
        -e "PROJECT_NAME=$project_name" \
        "$AISEC_IMAGE" --format "$fmt" >"$out" 2>"$err" || status=$?
    else
      docker run --rm \
        --network none \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=16m \
        --cap-drop ALL \
        --security-opt no-new-privileges \
        --pids-limit 256 \
        --memory 256m \
        --user "${uid}:${gid}" \
        -e "CODEX_VERSION=$version" \
        -e "PROJECT_NAME=$project_name" \
        "${MOUNTS[@]}" \
        "$AISEC_IMAGE" --format "$fmt" >"$out" 2>"$err" || status=$?
    fi
    finish_capture "$name" "$status" "$dest" "${name}.err"
  }
  log "Running Codex Security Audit in a read-only container"
  local json_status html_status txt_status
  run_aisec_format json aisec-json aisec.json
  run_aisec_format html aisec-html aisec.html
  run_aisec_format report aisec-txt aisec.txt
  json_status="$(status_of aisec-json)"
  html_status="$(status_of aisec-html)"
  txt_status="$(status_of aisec-txt)"
  if [ "$json_status" -ne 0 ] || [ "$html_status" -ne 0 ] || [ "$txt_status" -ne 0 ]; then
    add_step "aisec-codex-audit" "error" "$json_status" "The container exited non-zero for at least one report format." \
      "raw/aisec.json" "raw/aisec.html" "raw/aisec.txt"
  else
    add_step "aisec-codex-audit" "ok" "0" "" \
      "raw/aisec.json" "raw/aisec.html" "raw/aisec.txt"
  fi
}

record_mdm() {
  local uname_s
  uname_s="$(uname)"
  if [ "$uname_s" != "Darwin" ] || ! command -v defaults >/dev/null 2>&1; then
    add_step "mdm" "skipped" "" \
      "defaults is only used on macOS for the com.openai.codex MDM payload; not running it here."
    return 0
  fi
  local status=0
  defaults read com.openai.codex requirements_toml_base64 \
    >"$REPORT_DIR/tmp/plain/mdm-defaults.out" \
    2>"$REPORT_DIR/tmp/plain/mdm-defaults.err" || status=$?
  add_step "mdm" "ok" "$status" ""
}

run_codex
run_mcp
run_access
run_aisec
record_mdm

"${PY[@]}" meta-set --meta "$META" --key redaction_replacements --value "$REDACTION_COUNT"
log "Recording watched files after scanners ran"
"${PY[@]}" snapshot \
  --home "$HOME" \
  --codex-home "$CODEX_HOME" \
  --xdg-config "$XDG_CONFIG" \
  --out "$REPORT_DIR/tmp/snapshot-after.json"

set +e
"${PY[@]}" assemble \
  --home "$HOME" \
  --codex-home "$CODEX_HOME" \
  --xdg-config "$XDG_CONFIG" \
  --report "$REPORT_DIR" \
  --before "$REPORT_DIR/tmp/snapshot-before.json" \
  --after "$REPORT_DIR/tmp/snapshot-after.json" \
  --meta "$META" \
  --out "$REPORT_DIR/audit.json"
assemble_status=$?
set -e

if [ -f "$REPORT_DIR/audit.json" ]; then
  "${PY[@]}" embed-report \
    --template "$ROOT/viewer/index.html" \
    --audit "$REPORT_DIR/audit.json" \
    --out "$REPORT_DIR/report.html"
fi

open_report() {
  local target="$1"
  if [ "$(uname)" = "Darwin" ]; then
    if command -v open >/dev/null 2>&1; then
      open "$target" || log "open could not launch a browser."
      return 0
    fi
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$target" >/dev/null 2>&1 || log "xdg-open could not launch a browser."
    return 0
  fi
  log "No browser launcher found (open on macOS, xdg-open on Linux)."
  return 0
}

log "Wrote $REPORT_DIR/audit.json"
if [ -f "$REPORT_DIR/report.html" ]; then
  log "Open this file in a browser:"
  printf '%s\n' "$REPORT_DIR/report.html"
  if [ "$OPEN_REPORT" -eq 1 ]; then
    open_report "$REPORT_DIR/report.html"
  fi
fi
cleanup
exit "$assemble_status"
