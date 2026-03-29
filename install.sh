#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[macaronV2] building Go binary (stable)..."
go mod tidy
go build -o macaron ./cmd/macaron

echo "[macaronV2] built ./macaron"
