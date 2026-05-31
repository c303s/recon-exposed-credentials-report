#!/usr/bin/env bash

set -euo pipefail

APP_NAME="recon-exposed-credentials-report"
SCRIPT_NAME="recon_exposed_credentials_report.py"
REPO_SLUG="${RECON_REPORT_REPO:-c303s/recon-exposed-credentials-report}"
REPO_BRANCH="${RECON_REPORT_BRANCH:-main}"
INSTALL_DIR="${RECON_REPORT_INSTALL_DIR:-$(pwd -P)}"
LAUNCHER_PATH="$INSTALL_DIR/$APP_NAME"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${APP_NAME}.XXXXXX")"

cleanup() {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: '$1' is required to install $APP_NAME." >&2
    exit 1
  fi
}

print_step() {
  echo "==> $1"
}

download_source() {
  if [[ -n "${RECON_REPORT_SOURCE_DIR:-}" ]]; then
    SOURCE_DIR="$RECON_REPORT_SOURCE_DIR"
    if [[ ! -f "$SOURCE_DIR/$SCRIPT_NAME" ]]; then
      echo "Error: RECON_REPORT_SOURCE_DIR does not contain $SCRIPT_NAME." >&2
      exit 1
    fi
    return
  fi

  need_command curl
  need_command tar

  local archive_path="$WORK_DIR/source.tar.gz"
  local repo_url="https://github.com/$REPO_SLUG/archive/refs/heads/$REPO_BRANCH.tar.gz"

  print_step "Downloading $APP_NAME from GitHub"
  curl -fsSL "$repo_url" -o "$archive_path"
  tar -xzf "$archive_path" -C "$WORK_DIR"

  SOURCE_DIR="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "$SOURCE_DIR" || ! -f "$SOURCE_DIR/$SCRIPT_NAME" ]]; then
    echo "Error: could not unpack the application files." >&2
    exit 1
  fi
}

create_launcher() {
  cat > "$LAUNCHER_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$INSTALL_DIR"
exec python3 "$INSTALL_DIR/$SCRIPT_NAME" "\$@"
EOF
  chmod 755 "$LAUNCHER_PATH"
}

install_files() {
  local existing_env_backup="$WORK_DIR/.env"
  local existing_env_bak_backup="$WORK_DIR/.env.bak"
  local file_name

  mkdir -p "$INSTALL_DIR"

  if [[ -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env" "$existing_env_backup"
  fi
  if [[ -f "$INSTALL_DIR/.env.bak" ]]; then
    cp "$INSTALL_DIR/.env.bak" "$existing_env_bak_backup"
  fi

  for file_name in "$SCRIPT_NAME" "README.md" "install.sh" ".gitignore"; do
    if [[ -f "$SOURCE_DIR/$file_name" ]]; then
      cp "$SOURCE_DIR/$file_name" "$INSTALL_DIR/$file_name"
    fi
  done

  chmod 755 "$INSTALL_DIR/$SCRIPT_NAME"
  if [[ -f "$INSTALL_DIR/install.sh" ]]; then
    chmod 755 "$INSTALL_DIR/install.sh"
  fi

  if [[ -f "$existing_env_backup" ]]; then
    cp "$existing_env_backup" "$INSTALL_DIR/.env"
  fi
  if [[ -f "$existing_env_bak_backup" ]]; then
    cp "$existing_env_bak_backup" "$INSTALL_DIR/.env.bak"
  fi

  create_launcher
}

launch_application() {
  if [[ "${RECON_REPORT_SKIP_LAUNCH:-0}" == "1" ]]; then
    print_step "Installation complete"
    echo "Run './$APP_NAME' from $INSTALL_DIR to start Recon Report."
    return
  fi

  print_step "Starting Recon Report"
  exec "$LAUNCHER_PATH"
}

main() {
  need_command python3
  download_source
  install_files
  launch_application
}

main "$@"