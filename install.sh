#!/usr/bin/env bash

set -euo pipefail

REPO_RAW_BASE="https://raw.githubusercontent.com/c303s/recon-exposed-credentials-report/main"
SCRIPT_NAME="recon-exposed-credentials-report"
SCRIPT_URL="$REPO_RAW_BASE/recon_exposed_credentials_report.py"

log() {
  printf '[install] %s\n' "$1"
}

ensure_homebrew() {
  return
}

ensure_python3() {
  if command -v python3 >/dev/null 2>&1; then
    return
  fi

  log "Python 3 is required but was not found on this system."
  log "Install Python 3 first, then run this installer again."
  exit 1
}

ensure_pip() {
  python3 -m ensurepip --upgrade >/dev/null 2>&1 || true
}

install_falconpy() {
  log "Installing FalconPy..."
  python3 -m pip install --user --upgrade pip falconpy
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

  printf '%s' "$target_path"
}

main() {
  ensure_python3
  ensure_pip
  install_falconpy

  local installed_cli
  installed_cli="$(install_cli)"

  log "Running initial setup..."
  "$installed_cli" --setup

  log "Installation complete. Run '$SCRIPT_NAME' to start the tool."
}

main "$@"