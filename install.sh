#!/usr/bin/env bash

set -euo pipefail

REPO_RAW_BASE="https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main"
SCRIPT_NAME="recon-exposed-credentials-report"
SCRIPT_URL="$REPO_RAW_BASE/recon_exposed_credentials_report.py"
PYTHON_BIN=""

log() {
  printf '[install] %s\n' "$1" >&2
}

ensure_homebrew() {
  return
}

select_python3() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if ! command -v "$candidate" >/dev/null 2>&1; then
      continue
    fi
    PYTHON_BIN="$candidate"
    return
  done

  log "Python 3 is required but was not found on this system."
  log "Install Python 3 first, then run this installer again."
  exit 1
}

choose_install_dir() {
  if [[ -w /usr/local/bin ]]; then
    printf '/usr/local/bin'
    return
  fi

  mkdir -p "$HOME/.local/bin"
  printf '%s' "$HOME/.local/bin"
}

install_cli() {
  local install_dir
  install_dir="$(choose_install_dir)"
  local target_path="$install_dir/$SCRIPT_NAME"

  log "Installing $SCRIPT_NAME to $target_path..."
  curl -fsSL "$SCRIPT_URL" -o "$target_path"
  chmod +x "$target_path"

  if [[ ":$PATH:" != *":$install_dir:"* ]]; then
    log "Add $install_dir to your PATH if it is not already available in your shell."
  fi

  printf '%s\n' "$target_path"
}

main() {
  select_python3
  log "Using $($PYTHON_BIN --version 2>&1)"

  local installed_cli
  installed_cli="$(install_cli | tail -n 1)"

  log "Running initial setup..."
  "$installed_cli" --setup

  log "Installation complete. Run '$SCRIPT_NAME' to start the tool."
}

main "$@"