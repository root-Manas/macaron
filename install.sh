#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if ! command -v go >/dev/null 2>&1; then
  echo "[!] Go is not installed. Install Go 1.22+ and rerun."
  exit 1
fi

mkdir -p "$HOME/.local/bin"
echo "[macaronV2] building binary..."
go mod tidy
go build -o "$HOME/.local/bin/macaron" ./cmd/macaron
chmod +x "$HOME/.local/bin/macaron"

if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

echo "[macaronV2] installed to $HOME/.local/bin/macaron"
echo "[macaronV2] run: macaron --version"
