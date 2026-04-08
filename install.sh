#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v go >/dev/null 2>&1; then
  echo "[!] Go is not installed. Install Go 1.22+ and rerun."
  exit 1
fi

mkdir -p "$HOME/.local/bin"
echo "[macaron] building binary..."
go mod tidy
go build -o "$HOME/.local/bin/macaron" ./cmd/macaron
chmod +x "$HOME/.local/bin/macaron"

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

add_to_profile() {
  local profile="$1"
  if [ -f "$profile" ] && ! grep -qF 'HOME/.local/bin' "$profile" 2>/dev/null; then
    echo "$PATH_LINE" >> "$profile"
    echo "[macaron] added PATH entry to $profile"
  fi
}

add_to_profile "$HOME/.bashrc"
add_to_profile "$HOME/.zshrc"
add_to_profile "$HOME/.profile"

echo "[macaron] installed to $HOME/.local/bin/macaron"
echo "[macaron] restart your shell or run:  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo "[macaron] then run:  macaron --version"
