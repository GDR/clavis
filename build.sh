#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building Clavis (GUI), clavis-cli (CLI), and age-plugin-clavis (Release)..."
swift build -c release

echo "🔐 Detecting Code Signing Identity..."
SIGN_IDENTITY="-"
if /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Clavis Local Development"; then
    SIGN_IDENTITY="Clavis Local Development"
    echo "  Using local certificate: 'Clavis Local Development'"
elif /usr/bin/security find-identity -v -p codesigning 2>/dev/null | grep -q "Apple Development"; then
    SIGN_IDENTITY="Apple Development"
    echo "  Using Apple Development certificate"
else
    echo "  No developer certificate found, falling back to ad-hoc signing (-)"
fi

echo "🔐 Signing binaries and embedding entitlements..."
BINARIES=(
    ".build/release/Clavis"
    ".build/release/clavis-cli"
    ".build/release/age-plugin-clavis"
)

for binary in "${BINARIES[@]}"; do
    if [[ ! -x "$binary" ]]; then
        echo "❌ Expected executable is missing: $binary" >&2
        exit 1
    fi

    /usr/bin/codesign \
        --force \
        --sign "$SIGN_IDENTITY" \
        --options runtime \
        --timestamp=none \
        --entitlements Entitlements.plist \
        "$binary"
    /usr/bin/codesign --verify --strict --verbose=2 "$binary"
done

echo "✅ Build, hardened runtime signing, and signature verification complete!"
echo ""
echo "🚀 To run Clavis GUI App & Socket Daemon:"
echo "  swift run Clavis"
echo "  or: .build/release/Clavis"
echo ""
echo "💻 To use Clavis CLI:"
echo "  swift run clavis-cli list"
echo "  swift run clavis-cli generate <label>"
echo "  swift run clavis-cli export-pub <label>"
echo "  swift run clavis-cli delete <label>"
echo ""
echo "🔑 To use with SSH:"
echo "  export SSH_AUTH_SOCK=~/.ssh/clavis.sock"
