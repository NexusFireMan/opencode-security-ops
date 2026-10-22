#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"
BACKUP="$DEST/install-backups/opencode-security-ops-$(date -u +%Y%m%dT%H%M%SZ)-$$"

usage() {
  cat <<'EOF'
Usage: bash install.sh [--check|--global|--uninstall]

  --check      Validate repository files; make no changes (default)
  --global     Install one skill, three agents, and four namespaced commands
  --uninstall  Remove only opencode-security-ops-owned paths

This installer never uses sudo, installs packages, edits shell profiles, or changes opencode.json.
EOF
}

check() {
  python3 -m unittest discover -s "$ROOT/tests" -v
  PYTHONPATH="$ROOT/.opencode/skills/opencode-security-ops/scripts" \
    python3 -m secops pipeline-plan --file "$ROOT/pipelines/web-api.json" >/dev/null
  echo "Checks passed."
}

guard_destination() {
  case "$DEST" in
    */opencode) ;;
    *) echo "Refusing unexpected destination: $DEST" >&2; exit 1 ;;
  esac
  for path in "$DEST" "$DEST/skills" "$DEST/agents" "$DEST/commands"; do
    if [[ -L "$path" ]]; then
      echo "Refusing symlinked install path: $path" >&2
      exit 1
    fi
  done
}

backup_if_present() {
  local target="$1" rel="$2"
  if [[ -e "$target" ]]; then
    mkdir -p "$BACKUP/$(dirname "$rel")"
    mv "$target" "$BACKUP/$rel"
  fi
}

install_global() {
  check
  guard_destination
  mkdir -p "$DEST/skills" "$DEST/agents" "$DEST/commands"
  backup_if_present "$DEST/skills/opencode-security-ops" "skills/opencode-security-ops"
  cp -a "$ROOT/.opencode/skills/opencode-security-ops" "$DEST/skills/opencode-security-ops"
  for agent in secops-orchestrator secops-reviewer secops-evidence-reviewer; do
    backup_if_present "$DEST/agents/$agent.md" "agents/$agent.md"
    cp "$ROOT/.opencode/agents/$agent.md" "$DEST/agents/$agent.md"
  done
  backup_if_present "$DEST/commands/secops" "commands/secops"
  mkdir -p "$DEST/commands"
  cp -a "$ROOT/.opencode/commands/secops" "$DEST/commands/secops"
  mkdir -p "$DEST/opencode-security-ops"
  cat >"$DEST/opencode-security-ops/install.json" <<EOF
{"installed_at":"$(date -u +%FT%TZ)","source":"$ROOT","version":"0.1.0"}
EOF
  echo "Installed into $DEST"
  [[ -d "$BACKUP" ]] && echo "Previous files backed up to $BACKUP"
}

uninstall_global() {
  guard_destination
  rm -rf "$DEST/skills/opencode-security-ops" "$DEST/commands/secops"
  rm -f "$DEST/agents/secops-orchestrator.md" "$DEST/agents/secops-reviewer.md" "$DEST/agents/secops-evidence-reviewer.md"
  rm -f "$DEST/opencode-security-ops/install.json"
  rmdir "$DEST/opencode-security-ops" 2>/dev/null || true
  echo "Removed opencode-security-ops-owned paths. Backups, if any, were preserved."
}

case "${1:---check}" in
  --check) check ;;
  --global) install_global ;;
  --uninstall) uninstall_global ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
