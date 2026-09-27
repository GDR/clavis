#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v just >/dev/null 2>&1; then
    exec just "$@"
elif command -v nix >/dev/null 2>&1; then
    exec nix shell nixpkgs#just --command just "$@"
else
    echo "❌ 'just' command runner is required. Install it via 'nix-shell -p just', 'brew install just', or 'cargo install just'." >&2
    exit 1
fi
